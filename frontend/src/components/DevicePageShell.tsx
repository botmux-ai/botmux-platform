import type { ReactNode } from 'react';
import { Button, Space, Typography } from '@arco-design/web-react';

export default function DevicePageShell({ title, subtitle, children, className = '' }: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <>
      <header className="app-header device-page-header">
        <a className="brand brand-link" href="/">
          <img className="brand-logo" src="/favicon.png" alt="" />
          botmux 平台
        </a>
        <Space size={8}>
          <Button size="small" type="text" onClick={() => (location.href = '/mobile')}>移动版</Button>
          <Button size="small" type="text" onClick={() => (location.href = '/devices')}>设备</Button>
          <Button size="small" type="text" onClick={() => (location.href = '/credentials')}>凭据</Button>
        </Space>
      </header>
      <main className={`app-wrap device-page-wrap ${className}`}>
        <div className="device-page-title">
          <Typography.Title heading={4}>{title}</Typography.Title>
          {subtitle && <Typography.Paragraph type="secondary">{subtitle}</Typography.Paragraph>}
        </div>
        {children}
      </main>
    </>
  );
}
