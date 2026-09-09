import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {MachinaEntryApp} from './app';

const root = document.getElementById('root');
if (root === null) {
  throw new Error('Machina web root element is missing.');
}

createRoot(root).render(
  <StrictMode>
    <MachinaEntryApp />
  </StrictMode>,
);
