// Resolve the loaded window, not the model's theoretical maximum.
export async function modelContext(config, fetcher = fetch) {
  let loaded;
  if ((config.provider ?? 'lmstudio') === 'lmstudio') {
    try {
      const url = new URL(config.endpoint ?? 'http://127.0.0.1:1234/v1');
      url.pathname = '/api/v0/models'; url.search = '';
      const response = await fetcher(url, {signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw Error(`HTTP ${response.status}`);
      const models = await response.json();
      loaded = models.data?.find(m => m.id === config.model && m.state === 'loaded')?.loaded_context_length;
    } catch (error) {
      if (config.requireLoadedContext) throw Error(`Cannot resolve loaded model context: ${error.message}`);
    }
  }
  if (config.requireLoadedContext && !Number.isSafeInteger(loaded)) throw Error('Requested model is not loaded or does not report its loaded context');
  const requested = config.contextTokens;
  if (requested !== undefined && (!Number.isSafeInteger(requested) || requested < 8192)) throw Error('contextTokens must be an integer >=8192');
  const contextTokens = Math.min(requested ?? loaded ?? 65536, loaded ?? Infinity);
  const outputTokens = config.outputTokens ?? 2048;
  if (!Number.isSafeInteger(outputTokens) || outputTokens < 128 || outputTokens > contextTokens / 4) throw Error('Invalid output token reserve');
  return {contextTokens, outputTokens, loadedContextTokens: loaded ?? null,
    contextSource: loaded ? 'lmstudio-loaded-model' : requested ? 'operator' : 'legacy-default',
    compaction: {enabled: true, reserveTokens: Math.max(outputTokens * 2, Math.floor(contextTokens * .25)), keepRecentTokens: Math.min(12000, Math.floor(contextTokens * .2))}};
}
