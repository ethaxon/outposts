declare global {
  interface Window {
    Prism: typeof import('prismjs');
    ClipboardJS: typeof import('clipboard')
  }
}

export { };
