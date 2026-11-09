import React, { lazy, Suspense } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import { shouldUseMobileShell } from './route';
import { editionPage } from '@edition/pages';

const App = lazy(() => import('./App'));
const DeviceConfirmPage = lazy(() => import('./DeviceConfirmPage'));
const DevicesPage = lazy(() => import('./DevicesPage'));
const CredentialsPage = lazy(() => import('./CredentialsPage'));
const MobileMachinesPage = lazy(() => import('./MobileMachinesPage'));

const path = location.pathname;
const EditionPage = editionPage(path);
let root: React.ReactNode;
if (EditionPage) root = <EditionPage />;
else if (path === '/devices/confirm' || path === '/devices/confirm/') root = <DeviceConfirmPage />;
else if (path === '/devices' || path === '/devices/') root = <DevicesPage />;
else if (path === '/credentials' || path === '/credentials/') root = <CredentialsPage />;
else {
  const narrow = window.matchMedia?.('(max-width: 600px)').matches ?? false;
  root = shouldUseMobileShell(path, location.search, narrow) ? <MobileMachinesPage /> : <App />;
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Suspense fallback={null}>{root}</Suspense>
  </React.StrictMode>,
);
