<p>Packages:</p>
<ul>
<li>
<a href="#lakom.extensions.gardener.cloud%2fv1alpha1">lakom.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="lakom.extensions.gardener.cloud/v1alpha1">lakom.extensions.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 contains the Lakom Shoot Service extension configuration.</p>
</p>
Resource Types:
<ul></ul>
<h3 id="lakom.extensions.gardener.cloud/v1alpha1.LakomConfig">LakomConfig
</h3>
<p>
<p>LakomConfig contains information about the Lakom service configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>scope</code></br>
<em>
github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom.ScopeType
</em>
</td>
<td>
<em>(Optional)</em>
<p>The scope in which lakom will verify pods</p>
</td>
</tr>
<tr>
<td>
<code>publicKeysSecretReference</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>CosignPublicKeys is the cosign public keys used to verify image signatures.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
