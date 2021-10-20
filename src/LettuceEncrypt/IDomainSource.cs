// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines a source for domains that will be considered for creation/renewal
    /// </summary>
    public interface IDomainSource
    {
        /// <summary>
        /// Gets a collection of domains that will be consdered for creation/renewal.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<IEnumerable<IDomainCert>> GetDomains(CancellationToken cancellationToken);
    }

    /// <summary>
    /// Defines a certificate request with one or multiple domains
    /// </summary>
    public interface IDomainCert
    {
        /// <summary>
        /// The primary domain which will be assigned the subject name
        /// </summary>
        public string PrimaryDomain { get; }

        /// <summary>
        /// Ordered domains the cert should be requested for, including <see cref="PrimaryDomain"/>
        /// </summary>
        public IEnumerable<string> Domains { get; }
    }

    /// <summary>
    /// Default single domain cert implemenation
    /// </summary>
    public class SingleDomainCert : IDomainCert
    {
        /// <inheritdoc/>
        public string PrimaryDomain { get; set; } = default!;

        /// <inheritdoc/>
        public IEnumerable<string> Domains => new[] { PrimaryDomain };
    }

    /// <summary>
    /// Default multiple domain cert implementation
    /// </summary>
    public class MultipleDomainCert : IDomainCert
    {
        /// <inheritdoc/>
        public string PrimaryDomain { get; set; } = default!;

        /// <inheritdoc/>
        public SortedSet<string> AlternateDomains { get; set; } = default!;

        /// <inheritdoc/>
        public IEnumerable<string> Domains
        {
            get
            {
                var ret = new SortedSet<string> { PrimaryDomain };
                ret.UnionWith(AlternateDomains);
                return ret;
            }
        }
    }
}
