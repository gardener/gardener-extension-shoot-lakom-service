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
<ul><li>
<a href="#lakom.extensions.gardener.cloud/v1alpha1.ScopeType">ScopeType</a>
</li></ul>
<h3 id="lakom.extensions.gardener.cloud/v1alpha1.ScopeType">ScopeType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#lakom.extensions.gardener.cloud/v1alpha1.LakomConfig">LakomConfig</a>)
</p>
<p>
</p>
<h3 id="lakom.extensions.gardener.cloud/v1alpha1.LakomConfig">LakomConfig
</h3>
<p>
<p>Configuration contains information about the Lakom service configuration.</p>
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
<code>scopeType</code></br>
<em>
<a href="#lakom.extensions.gardener.cloud/v1alpha1.ScopeType">
ScopeType
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The scope in which lakom will verify pods</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
