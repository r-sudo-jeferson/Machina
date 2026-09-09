import {forwardRef, type HTMLAttributes, type ReactNode} from 'react';

export type StatusTone = 'neutral' | 'success' | 'warning' | 'danger' | 'ai';

export interface StatusLampProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  tone: StatusTone;
  children?: ReactNode;
}

function hasMeaningfulContent(children: ReactNode): boolean {
  if (children === null || children === undefined || children === false || children === true) {
    return false;
  }
  if (typeof children === 'string') {
    return children.trim().length > 0;
  }
  return true;
}

export const StatusLamp = forwardRef<HTMLSpanElement, StatusLampProps>(function StatusLamp(
  {tone, children, className, 'aria-label': ariaLabel, ...props},
  ref,
) {
  const hasLabel = typeof ariaLabel === 'string' && ariaLabel.trim().length > 0;
  if (!hasLabel && !hasMeaningfulContent(children)) {
    throw new Error('StatusLamp requires text or an accessible label in addition to color.');
  }

  return (
    <span
      {...props}
      ref={ref}
      role="status"
      aria-label={ariaLabel}
      className={['alloy-status-lamp', className].filter(Boolean).join(' ')}
      data-alloy-tone={tone}
    >
      <span aria-hidden="true" className="alloy-status-lamp__indicator" />
      {children === null || children === undefined ? null : (
        <span className="alloy-status-lamp__label">{children}</span>
      )}
    </span>
  );
});
