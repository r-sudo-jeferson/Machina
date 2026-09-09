export function MachinaEntryApp() {
  return (
    <main aria-labelledby="machina-entry-title" aria-busy="true">
      <h1 id="machina-entry-title">Machina</h1>
      <div role="status" aria-live="polite" aria-atomic="true">
        Preparing your secure workspace…
      </div>
    </main>
  );
}
