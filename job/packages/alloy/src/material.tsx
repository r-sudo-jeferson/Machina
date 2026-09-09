import {forwardRef, type HTMLAttributes} from 'react';
import {
  alloyMaterialStates,
  alloyThemes,
  type AlloyMaterialState,
  type AlloyTheme,
} from '../generated/tokens';

function joinClassNames(...values: Array<string | undefined>): string {
  return values.filter((value): value is string => Boolean(value)).join(' ');
}

function assertTheme(theme: string): asserts theme is AlloyTheme {
  if (!(alloyThemes as readonly string[]).includes(theme)) {
    throw new Error(`Unsupported Alloy theme: ${theme}`);
  }
}

function assertMaterial(material: string): asserts material is AlloyMaterialState {
  if (!(alloyMaterialStates as readonly string[]).includes(material)) {
    throw new Error(`Unsupported Alloy material state: ${material}`);
  }
}

export interface AlloyChassisProps extends HTMLAttributes<HTMLDivElement> {
  theme: AlloyTheme;
}

export const AlloyChassis = forwardRef<HTMLDivElement, AlloyChassisProps>(function AlloyChassis(
  {theme, className, ...props},
  ref,
) {
  assertTheme(theme);

  return (
    <div
      {...props}
      ref={ref}
      className={joinClassNames('alloy-chassis', className)}
      data-alloy-theme={theme}
    />
  );
});

export interface AlloySurfaceProps extends HTMLAttributes<HTMLDivElement> {
  material?: AlloyMaterialState;
}

export const AlloySurface = forwardRef<HTMLDivElement, AlloySurfaceProps>(function AlloySurface(
  {material = 'convex-low', className, ...props},
  ref,
) {
  assertMaterial(material);

  return (
    <div
      {...props}
      ref={ref}
      className={joinClassNames('alloy-surface', className)}
      data-alloy-material={material}
    />
  );
});

export interface AlloyWellProps extends HTMLAttributes<HTMLDivElement> {
  material?: AlloyMaterialState;
}

export const AlloyWell = forwardRef<HTMLDivElement, AlloyWellProps>(function AlloyWell(
  {material = 'concave-low', className, ...props},
  ref,
) {
  assertMaterial(material);

  return (
    <div
      {...props}
      ref={ref}
      className={joinClassNames('alloy-well', className)}
      data-alloy-material={material}
    />
  );
});
