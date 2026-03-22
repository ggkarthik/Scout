type MetricInfoIconProps = {
  label: string;
  description: string;
  className?: string;
};

export function MetricInfoIcon({ label, description, className = '' }: MetricInfoIconProps) {
  const classes = ['metric-info-icon', className].filter(Boolean).join(' ');
  return (
    <button
      type="button"
      className={classes}
      aria-label={`${label}: ${description}`}
      title={description}
    >
      i
    </button>
  );
}
