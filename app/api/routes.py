from flask import Blueprint, jsonify
from app.models import HeroContent, FeatureCard, AboutContent, MedicalLoanContent, Testimonial

api = Blueprint('api', __name__)

@api.route('/hero', methods=['GET'])
def get_hero():
    """
    Retrieve hero section content
    """
    hero = HeroContent.query.first()
    return jsonify(hero.serialize()), 200

@api.route('/features', methods=['GET'])
def get_features():
    """
    Retrieve features section content
    """
    features = FeatureCard.query.all()
    return jsonify([feature.serialize() for feature in features]), 200

@api.route('/about', methods=['GET'])
def get_about():
    """
    Retrieve about section content
    """
    about = AboutContent.query.first()
    return jsonify(about.serialize()), 200

@api.route('/medical-loans', methods=['GET'])
def get_medical_loans():
    """
    Retrieve medical loans section content
    """
    loans = MedicalLoanContent.query.all()
    return jsonify([loan.serialize() for loan in loans]), 200

@api.route('/testimonials', methods=['GET'])
def get_testimonials():
    """
    Retrieve testimonials
    """
    testimonials = Testimonial.query.all()
    return jsonify([testimonial.serialize() for testimonial in testimonials]), 200
