// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
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
        private Dictionary<string, List<IDomainCert>> _domainCache = new Dictionary<string, List<IDomainCert>>();

        public DomainLoader(IOptions<LettuceEncryptOptions> options,
            IEnumerable<IDomainSource> domainSources,
            ILogger<DomainLoader> logger)
        {
            _options = options;
            _domainSources = domainSources;
            _logger = logger;
        }

        /// <summary>
        /// Load all domains from <see cref="LettuceEncryptOptions"/> and injected <see cref="IDomainSource"/>.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <param name="domainNames">The domain names to get certificates for.</param>
        /// <param name="refreshCache">Force a cache refresh.</param>
        /// <returns>Distinct set of domains to generate certs for.</returns>
        public async Task<IEnumerable<IDomainCert>> GetDomainCertsAsync(CancellationToken cancellationToken, IEnumerable<string> domainNames, bool refreshCache = false)
        {
            var firstDomainName = domainNames.First();

            if (_useCache && !refreshCache)
            {
                if (!_domainCache.ContainsKey(firstDomainName))
                {
                    _domainCache.Add(firstDomainName, new List<IDomainCert>());
                }
                return _domainCache[firstDomainName];
            }

            await s_sync.WaitAsync(cancellationToken);

            try
            {
                _logger.LogDebug("Loading domain sets");

                var options = _options.Value;

                var domains = new List<IDomainCert>();

                if (options != null && domainNames.ToList().Count > 0)
                {
                    domains.Add(new MultipleDomainCert
                    {
                        OrderedDomains = new HashSet<string>(domainNames)
                    });
                }

                foreach (var domainSource in _domainSources)
                {
                    _logger.LogDebug("Loading domains from {domainSource}", domainSource.GetType().Name);

                    domains.AddRange(await domainSource.GetDomains(cancellationToken));
                }

                if (!_domainCache.ContainsKey(firstDomainName))
                {
                    _domainCache.Add(firstDomainName, domains);
                }
                else
                {
                    _domainCache[firstDomainName] = domains;
                }
                _useCache = true;
            }
            finally
            {
                s_sync.Release();
            }

            return _domainCache[firstDomainName];
        }
    }
}
