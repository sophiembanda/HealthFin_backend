from flask import Blueprint, request, jsonify
from flask_login import login_required
from app import db
from app.models import HeroContent, FeatureCard, AboutContent, MedicalLoanContent, Testimonial

cms = Blueprint('cms', __name__)

@cms.route('/hero', methods=['GET', 'POST'])
@login_required
def manage_hero():
    """
    Retrieve and update hero section content
    """
    if request.method == 'POST':
        data = request.get_json()
        hero = HeroContent.query.first() or HeroContent()
        hero.title = data['title']
        hero.subtitle = data['subtitle']
        db.session.add(hero)
        db.session.commit()
        return jsonify({'message': 'Hero section updated successfully'}), 200
    else:
        hero = HeroContent.query.first()
        return jsonify(hero.serialize()), 200

@cms.route('/features', methods=['GET', 'POST'])
@login_required
def manage_features():
    """
    Retrieve and update features section content
    """
    if request.method == 'POST':
        data = request.get_json()
        feature = FeatureCard(title=data['title'], description=data['description'])
        db.session.add(feature)
        db.session.commit()
        return jsonify({'message': 'Feature added successfully'}), 200
    else:
        features = FeatureCard.query.all()
        return jsonify([feature.serialize() for feature in features]), 200

@cms.route('/about', methods=['GET', 'POST'])
@login_required
def manage_about():
    """
    Retrieve and update about section content
    """
    if request.method == 'POST':
        data = request.get_json()
        about = AboutContent.query.first() or AboutContent()
        about.content = data['content']
        db.session.add(about)
        db.session.commit()
        return jsonify({'message': 'About section updated successfully'}), 200
    else:
        about = AboutContent.query.first()
        return jsonify(about.serialize()), 200

@cms.route('/medical-loans', methods=['GET', 'POST'])
@login_required
def manage_medical_loans():
    """
    Retrieve and update medical loans section content
    """
    if request.method == 'POST':
        data = request.get_json()
        loan_content = MedicalLoanContent.query.first() or MedicalLoanContent()
        loan_content.content = data['content']
        db.session.add(loan_content)
        db.session.commit()
        return jsonify({'message': 'Medical loans section updated successfully'}), 200
    else:
        loans = MedicalLoanContent.query.all()
        return jsonify([loan.serialize() for loan in loans]), 200

@cms.route('/testimonials', methods=['GET', 'POST'])
@login_required
def manage_testimonials():
    """
    Retrieve and update testimonials content
    """
    if request.method == 'POST':
        data = request.get_json()
        testimonial = Testimonial(name=data['name'], feedback=data['feedback'])
        db.session.add(testimonial)
        db.session.commit()
        return jsonify({'message': 'Testimonial added successfully'}), 200
    else:
        testimonials = Testimonial.query.all()
        return jsonify([testimonial.serialize() for testimonial in testimonials]), 200
