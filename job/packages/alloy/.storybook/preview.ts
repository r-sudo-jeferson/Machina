import '../generated/tokens.css';
import '../src/alloy.css';
import type {Preview} from '@storybook/react-vite';

const themes = ['silver', 'space-black'] as const;
type Theme = (typeof themes)[number];

function resolveTheme(value: unknown): Theme {
  return themes.includes(value as Theme) ? (value as Theme) : 'silver';
}

const preview: Preview = {
  globalTypes: {
    alloyTheme: {
      description: 'Machina Alloy material theme',
      toolbar: {
        title: 'Theme',
        icon: 'paintbrush',
        items: [
          {value: 'silver', title: 'Silver'},
          {value: 'space-black', title: 'Space Black'},
        ],
        dynamicTitle: true,
      },
    },
  },
  initialGlobals: {
    alloyTheme: 'silver',
  },
  decorators: [
    (Story, context) => {
      document.documentElement.setAttribute(
        'data-alloy-theme',
        resolveTheme(context.globals.alloyTheme),
      );
      return Story();
    },
  ],
  parameters: {
    layout: 'centered',
  },
};

export default preview;
