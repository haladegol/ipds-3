/**
 * HADES Upload — Drag & drop file upload with pipeline preview
 */
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileSelected = document.getElementById('fileSelected');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const pipelinePreview = document.getElementById('pipelinePreview');
    const uploadForm = document.getElementById('uploadForm');

    if (!dropZone) return;

    // Click to upload
    dropZone.addEventListener('click', () => fileInput.click());

    // Drag events
    ['dragenter', 'dragover'].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });
    ['dragleave', 'drop'].forEach(evt => {
        dropZone.addEventListener(evt, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    // Drop files
    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFiles(files);
        }
    });

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleFiles(fileInput.files);
        }
    });

    function handleFiles(files) {
        const fileList = Array.from(files);
        const validFiles = fileList.filter(f => f.name.toLowerCase().endsWith('.csv'));
        
        if (validFiles.length === 0) {
            alert('Please upload CSV files only.');
            return;
        }

        if (validFiles.length < fileList.length) {
            alert(`Skipped ${fileList.length - validFiles.length} non-CSV files.`);
        }

        // Update file input with only valid files
        const dt = new DataTransfer();
        validFiles.forEach(f => dt.items.add(f));
        fileInput.files = dt.files;

        // Show file info
        if (validFiles.length === 1) {
            fileName.textContent = validFiles[0].name;
            fileSize.textContent = formatSize(validFiles[0].size);
        } else {
            const totalSize = validFiles.reduce((acc, f) => acc + f.size, 0);
            fileName.textContent = `${validFiles.length} files selected`;
            fileSize.textContent = `Total size: ${formatSize(totalSize)}`;
        }
        
        fileSelected.style.display = 'flex';

        // Show pipeline preview
        pipelinePreview.style.display = 'block';

        // Enable analyze button
        analyzeBtn.disabled = false;
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // Form submit — show loading state
    if (uploadForm) {
        uploadForm.addEventListener('submit', () => {
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = `
                <svg class="spinner" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10" stroke-dasharray="50" stroke-dashoffset="20"/>
                </svg>
                <span>Analyzing... Please wait</span>
            `;
            analyzeBtn.style.opacity = '0.7';

            // Animate pipeline steps
            const steps = ['step1', 'step2', 'step2b', 'step3'];
            steps.forEach((id, i) => {
                setTimeout(() => {
                    const el = document.getElementById(id);
                    if (el) {
                        el.classList.add('active');
                        if (i > 0) {
                            const prev = document.getElementById(steps[i - 1]);
                            if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
                        }
                    }
                }, i * 1500);
            });
        });
    }
});
