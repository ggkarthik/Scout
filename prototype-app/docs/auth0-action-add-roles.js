/**
 * Auth0 Action: Add roles to access token
 *
 * Deploy this in Auth0 Dashboard → Actions → Flows → Login → Custom Action.
 *
 * This action injects the user's Auth0 roles into the access token under a
 * namespaced claim so the Scout backend can map them to PLATFORM_OWNER and
 * other roles.
 *
 * Namespace matches VITE_AUTH0_AUDIENCE and APP_JWT_ROLES_CLAIM:
 *   https://api.hossstore.in/roles
 *
 * Required Auth0 setup before deploying:
 *   1. Create a Role named "PLATFORM_OWNER" in Auth0 Dashboard → User Management → Roles.
 *   2. Assign that role to the platform owner user(s).
 *   3. Register the API with identifier https://api.hossstore.in in Auth0 Dashboard → APIs.
 *   4. Deploy this Action and add it to the Login flow.
 */

exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://api.hossstore.in';

  // Inject roles into the access token (used by the Scout backend).
  const roles = event.authorization?.roles ?? [];
  if (roles.length > 0) {
    api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
  }

  // Optionally mirror into the ID token for frontend inspection.
  if (roles.length > 0) {
    api.idToken.setCustomClaim(`${namespace}/roles`, roles);
  }
};
