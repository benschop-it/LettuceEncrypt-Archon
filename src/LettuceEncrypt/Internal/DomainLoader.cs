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
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IEnumerable<IDomainSource> _domainSources;
        private readonly ILogger<DomainLoader> _logger;

        internal DomainLoader(IOptions<LettuceEncryptOptions> options,
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
        /// <returns>Distinct set of domains to generate certs for.</returns>
        public async Task<HashSet<string>> GetDomainsAsync(CancellationToken cancellationToken)
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

            return domains;
        }
    }
}
