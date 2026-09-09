import type {StorybookConfig} from '@storybook/react-vite';

const config = {
  stories: ['../src/**/*.stories.@(ts|tsx)'],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
} satisfies StorybookConfig;

export default config;
