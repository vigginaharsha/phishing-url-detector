/**
 * Real-Time Client-Side JavaScript for AI Phishing URL Detector
 * Features: Debounced real-time typing analysis, interactive sample presets,
 * dynamic chart updating, and asynchronous scan submission.
 */

document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const exampleBtns = document.querySelectorAll('.example-btn');
    const livePreviewCard = document.getElementById('live-preview-card');
    const liveBadge = document.getElementById('live-badge');
    const liveScore = document.getElementById('live-score');
    const liveLevel = document.getElementById('live-level');
    const liveIndicatorsList = document.getElementById('live-indicators-list');
    const scanForm = document.getElementById('scan-form');
    const submitBtn = document.getElementById('submit-btn');

    let debounceTimer = null;

    // 1. Example URL Quick Presets
    if (urlInput && exampleBtns) {
        exampleBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const sampleUrl = btn.getAttribute('data-url');
                urlInput.value = sampleUrl;
                urlInput.focus();
                triggerRealTimeScan(sampleUrl);
            });
        });
    }

    // 2. Real-Time Debounced Typing Scan Engine
    if (urlInput && livePreviewCard) {
        urlInput.addEventListener('input', (e) => {
            const rawVal = e.target.value.trim();

            clearTimeout(debounceTimer);
            if (!rawVal || rawVal.length < 4) {
                livePreviewCard.style.display = 'none';
                return;
            }

            // Debounce for 350ms to prevent spamming API while typing
            debounceTimer = setTimeout(() => {
                triggerRealTimeScan(rawVal);
            }, 350);
        });
    }

    async function triggerRealTimeScan(urlStr) {
        if (!livePreviewCard) return;

        try {
            livePreviewCard.style.display = 'block';
            livePreviewCard.style.opacity = '0.7';

            const response = await fetch('/api/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: urlStr })
            });

            if (!response.ok) {
                livePreviewCard.style.display = 'none';
                return;
            }

            const data = await response.json();
            livePreviewCard.style.opacity = '1';

            // Update real-time UI components
            if (liveBadge) {
                liveBadge.className = `status-badge ${data.prediction}`;
                liveBadge.textContent = `${data.prediction == 'SAFE' ? '🟢 SAFE' : (data.prediction == 'SUSPICIOUS' ? '🟡 SUSPICIOUS' : '🔴 PHISHING')}`;
            }

            if (liveScore) {
                liveScore.className = `risk-score-val ${data.prediction}`;
                liveScore.textContent = `${data.risk_score}/100`;
            }

            if (liveLevel) {
                liveLevel.textContent = `Real-Time Assessment: ${data.risk_level}`;
            }

            if (liveIndicatorsList) {
                liveIndicatorsList.innerHTML = '';
                // Render top 3 key real-time indicators
                data.indicators.slice(0, 3).forEach(ind => {
                    const item = document.createElement('div');
                    item.className = `indicator-card ${ind.status}`;
                    item.style.padding = '0.6rem 0.9rem';
                    item.style.fontSize = '0.85rem';
                    item.innerHTML = `
                        <div class="indicator-icon">${ind.icon}</div>
                        <div>
                            <strong style="color:var(--text-primary);">${ind.title}:</strong>
                            <span style="color:var(--text-secondary);">${ind.description}</span>
                        </div>
                    `;
                    liveIndicatorsList.appendChild(item);
                });
            }

        } catch (err) {
            console.error('Real-time API error:', err);
            if (livePreviewCard) livePreviewCard.style.display = 'none';
        }
    }

    // 3. Form Submit Loading Animation
    if (scanForm && submitBtn) {
        scanForm.addEventListener('submit', (e) => {
            const rawVal = urlInput.value.trim();
            if (!rawVal) {
                e.preventDefault();
                alert('Please enter a valid URL string to scan.');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <span class="spinner" style="display:inline-block; width:18px; height:18px; border:2px solid #000; border-top-color:transparent; border-radius:50%; animation:spin 0.6s linear infinite;"></span>
                Processing Real-Time Inference...
            `;
        });
    }

    // Keyframe spin injection
    if (!document.getElementById('spinner-style')) {
        const style = document.createElement('style');
        style.id = 'spinner-style';
        style.innerHTML = `@keyframes spin { to { transform: rotate(360deg); } }`;
        document.head.appendChild(style);
    }
});
