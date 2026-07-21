#!/bin/sh
set -eu

mode="${1:---dry-run}"
: "${APP_PRODUCTION_FORBIDDEN_IDENTITY_SUBJECTS:?APP_PRODUCTION_FORBIDDEN_IDENTITY_SUBJECTS is required}"
: "${DB_URL:?DB_URL is required}"
: "${DB_USERNAME:?DB_USERNAME is required}"
: "${DB_PASSWORD:?DB_PASSWORD is required}"

export PGPASSWORD="$DB_PASSWORD"
database_url="${DB_URL#jdbc:}"

if [ "$mode" = "--dry-run" ]; then
  exec psql "$database_url" -U "$DB_USERNAME" -X -v ON_ERROR_STOP=1 \
    -v subjects="$APP_PRODUCTION_FORBIDDEN_IDENTITY_SUBJECTS" -P pager=off -c "
      with forbidden as (
        select lower(trim(value)) subject from regexp_split_to_table(:'subjects', ',') value
      )
      select u.id, u.external_subject, u.email, u.status, u.platform_owner,
             (u.password_hash is not null) has_password,
             count(distinct r.id) global_roles,
             count(distinct m.id) active_memberships
      from platform.app_users u
      join forbidden f on f.subject in (lower(u.external_subject), lower(coalesce(u.email, '')))
      left join platform.app_user_global_roles r on r.app_user_id=u.id
      left join platform.tenant_memberships m on m.user_id=u.id and upper(m.status)='ACTIVE'
      group by u.id order by u.external_subject;"
fi

if [ "$mode" != "--apply" ]; then
  echo "Usage: $0 --dry-run|--apply" >&2
  exit 2
fi

psql "$database_url" -U "$DB_USERNAME" -X -v ON_ERROR_STOP=1 \
  -v subjects="$APP_PRODUCTION_FORBIDDEN_IDENTITY_SUBJECTS" -c "
    begin;
    create temporary table cleanup_targets on commit drop as
      select u.id, u.external_subject
      from platform.app_users u
      where lower(u.external_subject) in (
          select lower(trim(value)) from regexp_split_to_table(:'subjects', ',') value)
         or lower(coalesce(u.email, '')) in (
          select lower(trim(value)) from regexp_split_to_table(:'subjects', ',') value);
    update platform.tenant_memberships set status='SUSPENDED', updated_at=now()
      where user_id in (select id from cleanup_targets);
    delete from platform.app_user_global_roles where app_user_id in (select id from cleanup_targets);
    update platform.app_users
      set status='SUSPENDED', platform_owner=false, password_hash=null, password_set_at=null,
          password_setup_token_hash=null, password_setup_token_expires_at=null, updated_at=now()
      where id in (select id from cleanup_targets);
    insert into tenant_default.audit_events
      (id, occurred_at, actor_subject, actor_role, action, target_type, target_id, outcome, details_json)
      select gen_random_uuid(), now(), 'system:production-identity-cleanup', 'PLATFORM_OWNER',
             'production.identity.suspended', 'app_user', id::text, 'SUCCESS',
             jsonb_build_object('externalSubject', external_subject)
      from cleanup_targets;
    commit;"
