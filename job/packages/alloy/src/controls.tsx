import {
  Button as AriaButton,
  FieldError,
  Input,
  Label,
  ProgressBar,
  Switch as AriaSwitch,
  TextField as AriaTextField,
  composeRenderProps,
  type ButtonProps as AriaButtonProps,
  type InputProps,
  type SwitchProps as AriaSwitchProps,
  type TextFieldProps as AriaTextFieldProps,
} from 'react-aria-components';
import {forwardRef, type ReactNode} from 'react';

function joinClassNames(...values: Array<string | undefined>): string {
  return values.filter((value): value is string => Boolean(value)).join(' ');
}

export interface ButtonProps extends AriaButtonProps {
  pendingLabel?: string;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {children, className, pendingLabel = 'In progress', 'aria-label': ariaLabel, ...props},
  ref,
) {
  const stableAccessibleName = ariaLabel ?? (typeof children === 'string' ? children : undefined);
  const accessibleNameProps = stableAccessibleName === undefined
    ? {}
    : {'aria-label': stableAccessibleName};

  return (
    <AriaButton
      {...props}
      {...accessibleNameProps}
      ref={ref}
      className={composeRenderProps(className, (resolvedClassName) =>
        joinClassNames('alloy-button', resolvedClassName)
      )}
    >
      {(renderProps) => {
        const renderedChildren = typeof children === 'function' ? children(renderProps) : children;
        return (
          <>
            <span className="alloy-button__content">{renderedChildren}</span>
            {renderProps.isPending ? (
              <ProgressBar
                aria-label={pendingLabel}
                className="alloy-button__progress"
                isIndeterminate
              >
                <span
                  aria-hidden="true"
                  className="alloy-button__progress-indicator"
                  data-alloy-motion="status"
                />
              </ProgressBar>
            ) : null}
          </>
        );
      }}
    </AriaButton>
  );
});

export interface IconButtonProps extends Omit<ButtonProps, 'aria-label'> {
  label: string;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  {label, className, children, ...props},
  ref,
) {
  if (label.trim().length === 0) {
    throw new Error('IconButton requires a non-empty accessible label.');
  }

  return (
    <Button
      {...props}
      ref={ref}
      aria-label={label}
      className={composeRenderProps(className, (resolvedClassName) =>
        joinClassNames('alloy-icon-button', resolvedClassName)
      )}
    >
      {children}
    </Button>
  );
});

export interface TextFieldProps extends Omit<AriaTextFieldProps, 'children'> {
  label: ReactNode;
  errorMessage?: ReactNode;
  placeholder?: string;
  inputClassName?: InputProps['className'];
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  {
    label,
    errorMessage,
    placeholder,
    className,
    inputClassName,
    ...props
  },
  ref,
) {
  const placeholderProps = placeholder === undefined ? {} : {placeholder};

  return (
    <AriaTextField
      {...props}
      className={composeRenderProps(className, (resolvedClassName) =>
        joinClassNames('alloy-text-field', resolvedClassName)
      )}
    >
      <Label className="alloy-label">{label}</Label>
      <Input
        {...placeholderProps}
        ref={ref}
        className={composeRenderProps(inputClassName, (resolvedClassName) =>
          joinClassNames('alloy-input', resolvedClassName)
        )}
      />
      {errorMessage === undefined ? null : (
        <FieldError className="alloy-field-error">{errorMessage}</FieldError>
      )}
    </AriaTextField>
  );
});

export interface SwitchProps extends AriaSwitchProps {}

export const Switch = forwardRef<HTMLLabelElement, SwitchProps>(function Switch(
  {children, className, ...props},
  ref,
) {
  return (
    <AriaSwitch
      {...props}
      ref={ref}
      className={composeRenderProps(className, (resolvedClassName) =>
        joinClassNames('alloy-switch', resolvedClassName)
      )}
    >
      {(renderProps) => (
        <>
          <span aria-hidden="true" className="alloy-switch__track">
            <span className="alloy-switch__thumb" />
          </span>
          <span className="alloy-switch__label">
            {typeof children === 'function' ? children(renderProps) : children}
          </span>
        </>
      )}
    </AriaSwitch>
  );
});
