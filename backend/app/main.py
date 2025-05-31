from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import User, ScanHistory
import random

main_bp = Blueprint('main', __name__)

@main_bp.route('/', methods=['GET'])
def get_routes():
    """Get all available routes"""
    routes = [
        '/api/auth/register',
        '/api/auth/login',
        '/api/auth/refresh',
        '/api/auth/profile',
        '/api/auth/test',
        '/api/dashboard',
        '/api/scan-history',
        '/api/scan/file',
        '/api/scan/url'
    ]
    return jsonify({'routes': routes}), 200

@main_bp.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    """Get dashboard data"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's scan history
        scans = ScanHistory.query.filter_by(user_id=current_user_id).order_by(ScanHistory.created_at.desc()).limit(10).all()
        
        # Calculate stats
        total_scans = ScanHistory.query.filter_by(user_id=current_user_id).count()
        file_scans = ScanHistory.query.filter_by(user_id=current_user_id, scan_type='file').count()
        url_scans = ScanHistory.query.filter_by(user_id=current_user_id, scan_type='url').count()
        malicious_scans = ScanHistory.query.filter_by(user_id=current_user_id, result='malicious').count()
        safe_scans = ScanHistory.query.filter_by(user_id=current_user_id, result='safe').count()
        
        return jsonify({
            'user': user.to_dict(),
            'stats': {
                'total_scans': total_scans,
                'files_scanned': file_scans,
                'urls_scanned': url_scans,
                'threats_detected': malicious_scans,
                'safe_items': safe_scans
            },
            'recent_scans': [scan.to_dict() for scan in scans]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to load dashboard'}), 500

@main_bp.route('/scan-history', methods=['GET'])
@jwt_required()
def get_scan_history():
    """Get user's scan history"""
    try:
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        scans = ScanHistory.query.filter_by(user_id=current_user_id)\
                                .order_by(ScanHistory.created_at.desc())\
                                .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans.items],
            'total': scans.total,
            'pages': scans.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get scan history'}), 500

@main_bp.route('/scan/file', methods=['POST'])
@jwt_required()
def scan_file():
    """Simulate file scanning"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        filename = data.get('filename')
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
        
        # Simulate scan result (random for demo)
        is_malicious = random.random() < 0.3  # 30% chance of being malicious
        result = 'malicious' if is_malicious else 'safe'
        confidence = random.randint(70, 99)
        
        # Save scan result
        scan = ScanHistory(
            user_id=current_user_id,
            scan_type='file',
            target=filename,
            result=result,
            details=f'Confidence: {confidence}%'
        )
        db.session.add(scan)
        db.session.commit()
        
        return jsonify({
            'scan_id': scan.id,
            'filename': filename,
            'result': result,
            'is_malicious': is_malicious,
            'confidence': confidence,
            'details': {
                'scan_time': '2.3 seconds',
                'threats_found': ['Trojan.Generic'] if is_malicious else [],
                'file_size': f'{random.randint(100, 5000)} KB'
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'File scan failed'}), 500

@main_bp.route('/scan/url', methods=['POST'])
@jwt_required()
def scan_url():
    """Scan URL using AI phishing model"""
    try:
        from transformers import pipeline
        current_user_id = get_jwt_identity()
        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Load the model once (you may move this outside the function in production for efficiency)
        url_classifier = pipeline(
            "text-classification",
            model="models/url_phishing_model",
            tokenizer="models/url_phishing_model"
        )

        # Predict
        result = url_classifier(url)[0]
        label = result['label']
        confidence = round(result['score'] * 100, 2)
        is_malicious = label.lower() != 'safe'
        classification_method = "transformers-pipeline"

        # Save result in DB
        from app.models import ScanHistory
        from app import db

        scan = ScanHistory(
            user_id=current_user_id,
            scan_type='url',
            target=url,
            result='malicious' if is_malicious else 'safe',
            details=f'Model: {classification_method} | Confidence: {confidence}%'
        )
        db.session.add(scan)
        db.session.commit()

        return jsonify({
            'scan_id': scan.id,
            'url': url,
            'is_malicious': is_malicious,
            'confidence': confidence,
            'details': {
                'classification_method': classification_method,
                'scan_time': 'Instant',
                'model_confidence': f'{confidence}%',
                'domain_reputation': 'Unknown',
                'threats_found': [label] if is_malicious else [],
                'ai_analysis': f'Model classified URL as {label} with {confidence}%',
                'recommendation': 'Avoid clicking this link' if is_malicious else 'URL appears safe'
            }
        }), 200

    except Exception as e:
        from app import db
        db.session.rollback()
        return jsonify({'error': 'AI URL scan failed', 'details': str(e)}), 500

@main_bp.route('/about', methods=['GET'])
def about():
    """Get about information"""
    return jsonify({
        'name': 'ScaniFY API',
        'version': '1.0.0',
        'description': 'Advanced cybersecurity scanning platform',
        'features': [
            'File malware detection',
            'URL threat analysis',
            'Real-time scanning',
            'User authentication',
            'Scan history tracking'
        ]
    }), 200