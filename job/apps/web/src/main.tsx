import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import '../../../packages/alloy/src/alloy.css';
import './app.css';
import {MachinaEntryApp} from './app';
import {createBrowserEntryGateway} from './entry/http-gateway';

const root = document.getElementById('root');
if (root === null) {
  throw new Error('Machina web root element is missing.');
}

const entryGateway = createBrowserEntryGateway();

createRoot(root).render(
  <StrictMode>
    <MachinaEntryApp gateway={entryGateway} />
  </StrictMode>,
);
