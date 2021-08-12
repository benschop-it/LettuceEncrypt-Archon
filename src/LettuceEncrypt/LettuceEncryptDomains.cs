// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt
{
    /// <summary>
    /// Helper class to retrieve domains from all <see cref="IDomainSource"/> and <see cref="LettuceEncryptOptions"/>
    /// </summary>
    public class LettuceEncryptDomains
    {
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IEnumerable<IDomainSource> _domainSources;

        /// <summary>
        /// Helper class to retrieve domains from all <see cref="IDomainSource"/> and <see cref="LettuceEncryptOptions"/>
        /// </summary>
        /// <param name="options"></param>
        /// <param name="domainSources"></param>
        public LettuceEncryptDomains(IOptions<LettuceEncryptOptions> options,
            IEnumerable<IDomainSource> domainSources)
        {
            _options = options;
            _domainSources = domainSources;
        }

        /// <summary>
        /// Get all domains, grouped by their lowest
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns>Domains</returns>
        public async Task<IEnumerable<HashSet<string>>> GetDomainsAsync(CancellationToken cancellationToken)
        {
            var options = _options.Value;

            var domains = new Dictionary<string, HashSet<string>>();
            if (options != null && options.DomainNames.Length > 0)
            {
                domains[options.DomainNames[0]] = new HashSet<string>(options.DomainNames);
            }

            foreach (var domainSource in _domainSources)
            {
                var domainSourceDomains = await domainSource.GetDomainsAsync(cancellationToken);
                foreach (var domainGroup in domainSourceDomains)
                {
                    if (!domains.TryGetValue(domainGroup.Key, out var domainGroupDomains))
                    {
                        domains[domainGroup.Key] = domainGroup.Value;
                    }
                    else
                    {
                        domainGroupDomains.UnionWith(domainGroup.Value);
                    }
                }
            }

            return domains.Values;
        }
    }
}
