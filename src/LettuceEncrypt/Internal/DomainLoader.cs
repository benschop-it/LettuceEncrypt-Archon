// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt
{
    internal class DomainLoader : IDomainLoader
    {
        private static readonly SemaphoreSlim s_sync = new SemaphoreSlim(1, 1);

        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IEnumerable<IDomainSource> _domainSources;
        private readonly ILogger<DomainLoader> _logger;

        private bool _useCache = false;
        private HashSet<string> _domainCache = new HashSet<string>();

        public DomainLoader(IOptions<LettuceEncryptOptions> options,
            IEnumerable<IDomainSource> domainSources,
            ILogger<DomainLoader> logger)
        {
            _options = options;
            _domainSources = domainSources;
            _logger = logger;
        }

        internal async Task InvalidateCacheAsync(CancellationToken cancellationToken)
        {
            await s_sync.WaitAsync(cancellationToken);

            try
            {
                _useCache = false;
            }
            finally
            {
                s_sync.Release();
            }
        }

        /// <summary>
        /// Load all domains from <see cref="LettuceEncryptOptions"/> and injected <see cref="IDomainSource"/>.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>Distinct set of domains to generate certs for.</returns>
        public async Task<IReadOnlyCollection<string>> GetDomainsAsync(CancellationToken cancellationToken)
        {
            if (_useCache)
            {
                return _domainCache;
            }

            await s_sync.WaitAsync(cancellationToken);

            try
            {
                _logger.LogDebug("Loading domain sets");

                var options = _options.Value;

                var domains = new HashSet<string>();

                if (options != null && options.DomainNames.Length > 0)
                {
                    domains.UnionWith(options.DomainNames);
                }

                foreach (var domainSource in _domainSources)
                {
                    _logger.LogDebug("Loading domains from {domainSource}", domainSource.GetType().Name);

                    domains.UnionWith(await domainSource.GetDomains(cancellationToken));
                }

                _domainCache = domains;
                _useCache = true;
            }
            finally
            {
                s_sync.Release();
            }

            return _domainCache;
        }
    }
}
