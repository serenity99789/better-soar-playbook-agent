// Tab switching
function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Add active class to clicked tab
    event.target.classList.add('active');
    
    // Load templates if templates tab is selected
    if (tabName === 'templates') {
        loadTemplates();
    }
}

// Toggle input type
function toggleInputType() {
    const inputType = document.getElementById('input-type').value;
    const textInput = document.getElementById('text-input');
    const fileInput = document.getElementById('file-input');
    
    if (inputType === 'text') {
        textInput.style.display = 'block';
        fileInput.style.display = 'none';
    } else {
        textInput.style.display = 'none';
        fileInput.style.display = 'block';
    }
}

// File upload handling
const fileDropZone = document.getElementById('file-drop-zone');
const fileInputField = document.getElementById('file-input-field');

fileDropZone.addEventListener('click', () => {
    fileInputField.click();
});

fileDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    fileDropZone.classList.add('dragover');
});

fileDropZone.addEventListener('dragleave', () => {
    fileDropZone.classList.remove('dragover');
});

fileDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    fileDropZone.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInputField.files = files;
        updateFileDisplay(files[0]);
    }
});

fileInputField.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        updateFileDisplay(e.target.files[0]);
    }
});

function updateFileDisplay(file) {
    const fileDropZone = document.getElementById('file-drop-zone');
    fileDropZone.innerHTML = `
        <p>📄 ${file.name}</p>
        <p style="font-size: 0.9rem; color: #6c757d;">Size: ${(file.size / 1024).toFixed(2)} KB</p>
        <button type="button" class="btn btn-secondary" onclick="clearFile()">Remove File</button>
    `;
}

function clearFile() {
    fileInputField.value = '';
    const fileDropZone = document.getElementById('file-drop-zone');
    fileDropZone.innerHTML = `
        <p>📁 Drag and drop file here or click to browse</p>
        <p style="font-size: 0.9rem; color: #6c757d; margin-top: 10px;">Supported formats: .txt, .json, .csv, .log, .irp</p>
    `;
}

// Generate playbook form submission
document.getElementById('playbook-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const inputType = document.getElementById('input-type').value;
    const platform = document.getElementById('platform').value;
    const category = document.getElementById('category').value;
    const severity = document.getElementById('severity').value;
    
    const resultsDiv = document.getElementById('generate-results');
    resultsDiv.innerHTML = '<div class="loading">🔄 Generating playbook...</div>';
    
    try {
        let response;
        const options = { category, severity };
        
        if (inputType === 'text') {
            const text = document.getElementById('playbook-text').value;
            if (!text.trim()) {
                throw new Error('Please enter a security event description');
            }
            
            response = await fetch('/api/playbook/generate/text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    text,
                    platform,
                    options
                })
            });
        } else {
            if (!fileInputField.files.length) {
                throw new Error('Please select a file to upload');
            }
            
            const formData = new FormData();
            formData.append('file', fileInputField.files[0]);
            formData.append('platform', platform);
            formData.append('options', JSON.stringify(options));
            
            response = await fetch('/api/playbook/generate/file', {
                method: 'POST',
                body: formData
            });
        }
        
        const result = await response.json();
        
        if (result.success) {
            displayPlaybookResult(result.playbook, result.metadata);
        } else {
            resultsDiv.innerHTML = `<div class="error">❌ Error: ${result.error}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
    }
});

// Display playbook result
function displayPlaybookResult(playbook, metadata) {
    const resultsDiv = document.getElementById('generate-results');
    
    const mitreTags = playbook.use_case.mitre_techniques.map(tech => 
        `<span class="mitre-tag">${tech}</span>`
    ).join('');
    
    const queriesHtml = playbook.queries.map(query => `
        <div class="query-block">
            <strong>${query.name || 'Detection Query'} (${query.platform})</strong><br>
            ${query.query}
        </div>
    `).join('');
    
    const actionsHtml = playbook.actions.actions.map(action => `
        <div style="margin: 5px 0;">
            <strong>• ${action.name}:</strong> ${action.description}
            ${action.conditional ? `<br><em>Condition: ${action.condition}</em>` : ''}
        </div>
    `).join('');
    
    resultsDiv.innerHTML = `
        <div class="playbook-result">
            <div class="playbook-header">
                <div class="playbook-title">${playbook.playbook_name}</div>
                <span class="relevance-score">Risk Score: ${playbook.use_case.risk_model.risk_score}</span>
            </div>
            
            <div class="playbook-meta">
                <div class="meta-item">🏷️ ID: ${playbook.use_case.use_case_metadata.use_case_id}</div>
                <div class="meta-item">📊 Platform: ${playbook.platform}</div>
                <div class="meta-item">⚡ Severity: ${playbook.use_case.risk_model.base_severity}</div>
                <div class="meta-item">📅 Created: ${new Date(metadata.generated_at).toLocaleString()}</div>
            </div>
            
            <div class="playbook-meta">
                <div class="meta-item">📂 Category: ${playbook.use_case.use_case_metadata.category}</div>
                <div class="meta-item">🔍 Sub-Category: ${playbook.use_case.use_case_metadata.sub_category}</div>
            </div>
            
            <div>
                <strong>Description:</strong><br>
                ${playbook.use_case.use_case_metadata.description}
            </div>
            
            <div style="margin: 15px 0;">
                <strong>MITRE ATT&CK Techniques:</strong><br>
                <div class="mitre-tags">${mitreTags}</div>
            </div>
            
            <div style="margin: 15px 0;">
                <strong>Detection Logic:</strong><br>
                ${playbook.use_case.detection_logic.conditions.map(condition => 
                    `• ${condition.field} ${condition.operator} ${condition.value}`
                ).join('<br>')}
            </div>
            
            <div style="margin: 15px 0;">
                <strong>Generated Queries:</strong><br>
                ${queriesHtml}
            </div>
            
            <div style="margin: 15px 0;">
                <strong>Response Actions:</strong><br>
                ${actionsHtml}
            </div>
            
            ${playbook.use_case.response_orchestration.approval_required ? 
                '<div class="error" style="margin-top: 15px;">⚠️ Approval Required: This playbook requires manual approval for execution.</div>' : 
                ''
            }
            
            <div style="margin-top: 20px;">
                <button class="btn btn-primary" onclick="exportPlaybook('${playbook.playbook_id}', 'json')">📥 Export JSON</button>
                <button class="btn btn-secondary" onclick="exportPlaybook('${playbook.playbook_id}', 'markdown')">📄 Export Markdown</button>
            </div>
        </div>
    `;
    
    // Store playbook for export
    window.currentPlaybook = playbook;
}

// Reverse query search form submission
document.getElementById('reverse-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const query = document.getElementById('reverse-query').value;
    const platform = document.getElementById('reverse-platform').value;
    const category = document.getElementById('reverse-category').value;
    const severity = document.getElementById('reverse-severity').value;
    
    const resultsDiv = document.getElementById('reverse-results');
    resultsDiv.innerHTML = '<div class="loading">🔄 Searching for matching playbooks...</div>';
    
    try {
        if (!query.trim()) {
            throw new Error('Please enter a query to search');
        }
        
        const filters = {};
        if (category) filters.category = category;
        if (severity) filters.severity = severity;
        
        const response = await fetch('/api/playbook/reverse-search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                query,
                platform,
                filters
            })
        });
        
        const result = await response.json();
        
        if (result.results) {
            displayReverseResults(result);
        } else {
            resultsDiv.innerHTML = `<div class="error">❌ Error: ${result.error}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">❌ Error: ${error.message}</div>`;
    }
});

// Display reverse search results
function displayReverseResults(searchResult) {
    const resultsDiv = document.getElementById('reverse-results');
    
    if (searchResult.results.length === 0) {
        resultsDiv.innerHTML = `
            <div class="success">
                ℹ️ No matching playbooks found for your query.
            </div>
        `;
        return;
    }
    
    const resultsHtml = searchResult.results.map(result => {
        const mitreTags = result.playbook.use_case.mitre_techniques.map(tech => 
            `<span class="mitre-tag">${tech}</span>`
        ).join('');
        
        const reverseQueriesHtml = result.reverse_queries.map(query => `
            <div class="reverse-query">
                <strong>${query.type}:</strong> ${query.query}
            </div>
        `).join('');
        
        const matchedElementsHtml = `
            <div class="matched-elements">
                <strong>Matched:</strong> 
                ${result.matched_elements.fields.length > 0 ? `Fields (${result.matched_elements.fields.join(', ')})` : ''}
                ${result.matched_elements.functions.length > 0 ? `Functions (${result.matched_elements.functions.join(', ')})` : ''}
                ${result.matched_elements.techniques.length > 0 ? `Techniques (${result.matched_elements.techniques.map(t => t.id).join(', ')})` : ''}
            </div>
        `;
        
        return `
            <div class="reverse-result">
                <div class="playbook-header">
                    <div class="playbook-title">${result.playbook.playbook_name}</div>
                    <span class="relevance-score">Relevance: ${result.relevance_score}%</span>
                </div>
                
                <div class="playbook-meta">
                    <div class="meta-item">🏷️ ID: ${result.playbook.use_case.use_case_metadata.use_case_id}</div>
                    <div class="meta-item">📊 Platform: ${result.playbook.platform}</div>
                    <div class="meta-item">⚡ Severity: ${result.playbook.use_case.risk_model.base_severity}</div>
                </div>
                
                <div class="mitre-tags">${mitreTags}</div>
                
                ${matchedElementsHtml}
                
                <div style="margin: 15px 0;">
                    <strong>Reverse Queries:</strong><br>
                    ${reverseQueriesHtml}
                </div>
            </div>
        `;
    }).join('');
    
    resultsDiv.innerHTML = `
        <div class="success">
            ✅ Found ${searchResult.results.length} matching playbook(s) for your query.
        </div>
        ${resultsHtml}
    `;
}

// Load templates
async function loadTemplates() {
    const templatesDiv = document.getElementById('templates-list');
    templatesDiv.innerHTML = '<div class="loading">🔄 Loading templates...</div>';
    
    try {
        const response = await fetch('/api/templates/use-cases');
        const templates = await response.json();
        
        const templatesHtml = Object.entries(templates).map(([category, subcategories]) => {
            const subcategoriesHtml = Object.entries(subcategories).map(([subcat, template]) => `
                <div style="background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px;">
                    <h4 style="margin: 0 0 10px 0; color: #495057;">${template.subcategory}</h4>
                    <p style="margin: 0 0 10px 0; color: #6c757d;">${template.description}</p>
                    <div class="mitre-tags">
                        ${template.mitre_techniques.map(tech => `<span class="mitre-tag">${tech}</span>`).join('')}
                    </div>
                    <div style="margin-top: 10px;">
                        <small><strong>Data Sources:</strong> ${template.data_sources.join(', ')}</small>
                    </div>
                    <div style="margin-top: 10px;">
                        <small><strong>Severity:</strong> ${template.severity}</small>
                    </div>
                </div>
            `).join('');
            
            return `
                <div style="margin: 20px 0;">
                    <h3 style="color: #007bff; text-transform: capitalize;">${category}</h3>
                    ${subcategoriesHtml}
                </div>
            `;
        }).join('');
        
        templatesDiv.innerHTML = templatesHtml;
    } catch (error) {
        templatesDiv.innerHTML = `<div class="error">❌ Error loading templates: ${error.message}</div>`;
    }
}

// Export playbook
async function exportPlaybook(playbookId, format) {
    try {
        const response = await fetch('/api/playbook/export', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                playbook: window.currentPlaybook,
                format: format
            })
        });
        
        if (format === 'json') {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `playbook-${playbookId}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            const result = await response.text();
            const blob = new Blob([result], { type: 'text/markdown' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `playbook-${playbookId}.md`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
    } catch (error) {
        alert(`Error exporting playbook: ${error.message}`);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Set initial focus
    document.getElementById('playbook-text').focus();
});
