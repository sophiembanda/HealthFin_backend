from flask import Blueprint, request, jsonify, current_app
from app import db, mail, csrf
# from . import limiter
from flask_mail import Message
from app.models import ContactFormSubmission, Expense, Income, Savings, SavingPlan, Transaction, User, LoanApplication, ContactMessage
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import generate_csrf
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from app.decorators import csrf_exempt
from app.utils import validate_amount, validate_phone_number, validate_required_fields, validate_email, validate_contact_form
import logging
from app.services import send_contact_message
from sqlalchemy.orm.exc import NoResultFound

main = Blueprint('main', __name__)

savings_bp = Blueprint('savings', __name__, url_prefix='/api')

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@main.route('/api/contact', methods=['POST'])
@csrf_exempt
def contact():
    """
    Submit contact form data
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    if not name or not email or not message:
        return jsonify({'error': 'Missing required fields'}), 400

    submission = ContactFormSubmission(name=name, email=email, message=message)
    db.session.add(submission)
    db.session.commit()

    msg = Message('New Contact Form Submission', recipients=['admin@example.com'])
    msg.body = f"Name: {name}\nEmail: {email}\nMessage: {message}"
    msg.sender = current_app.config['MAIL_DEFAULT_SENDER']
    mail.send(msg)

    return jsonify({'message': 'Thank you for your message. We will get back to you soon.'}), 200

@main.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({"csrf_token": token})

@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"token": access_token}), 200


@main.route('/savings', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_savings():
    try:
        user_id = get_jwt_identity()
        savings = Savings.query.filter_by(user_id=user_id).first()

        if not savings:
            savings = Savings(user_id=user_id, balance=0)
            db.session.add(savings)
            db.session.commit()
            savings = Savings.query.filter_by(user_id=user_id).first()  # Re-fetch the savings object

        saving_plans = SavingPlan.query.all()
        saving_plans_data = [{"id": plan.id, "name": plan.name, "description": plan.description} for plan in saving_plans]
        return jsonify({"balance": savings.balance, "saving_plans": saving_plans_data}), 200
    except Exception as e:
        logger.error(f"Error fetching savings: {str(e)}")
        return jsonify({"error": "Error fetching savings"}), 500

@main.route('/savings/deposit', methods=['POST'])
@csrf.exempt
@jwt_required()
def add_deposit():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        amount = data.get('amount')
        
        if not validate_amount(amount):
            return jsonify({"error": "Invalid amount"}), 400

        savings = Savings.query.filter_by(user_id=user_id).first()
        if not savings:
            savings = Savings(user_id=user_id, balance=0)
            db.session.add(savings)
        
        savings.balance += amount
        transaction = Transaction(user_id=user_id, type='deposit', amount=amount)
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({"success": "Deposit added successfully", "balance": savings.balance}), 200
    except Exception as e:
        logger.error(f"Error adding deposit: {str(e)}")
        return jsonify({"error": "Error adding deposit"}), 500

@main.route('/savings/withdraw', methods=['POST'])
@csrf.exempt
@jwt_required()
def withdraw():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        amount = data.get('amount')
        
        if not validate_amount(amount):
            return jsonify({"error": "Invalid amount"}), 400

        savings = Savings.query.filter_by(user_id=user_id).first()
        if not savings or savings.balance < amount:
            return jsonify({"error": "Insufficient balance"}), 400

        savings.balance -= amount
        transaction = Transaction(user_id=user_id, type='withdraw', amount=amount)
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({"success": "Withdrawal successful", "balance": savings.balance}), 200
    except Exception as e:
        logger.error(f"Error processing withdrawal: {str(e)}")
        return jsonify({"error": "Error processing withdrawal"}), 500

@main.route('/saving-plans', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_saving_plans():
    try:
        saving_plans = SavingPlan.query.all()
        saving_plans_data = [{"id": plan.id, "name": plan.name, "description": plan.description} for plan in saving_plans]
        return jsonify(saving_plans_data), 200
    except Exception as e:
        logger.error(f"Error fetching saving plans: {str(e)}")
        return jsonify({"error": "Error fetching saving plans"}), 500

@main.route('/saving-plans/<int:id>', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_saving_plan(saving_plan_id):
    try:
        saving_plan = SavingPlan.query.get(saving_plan_id)
        if not saving_plan:
            return jsonify({"error": "Saving plan not found"}), 404
        
        return jsonify({
            "id": saving_plan.id,
            "name": saving_plan.name
        }), 200
    
    except NoResultFound:
        return jsonify({"error": "Saving plan not found"}), 404

@main.route('/savings/history', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_savings_history():
    try:
        user_id = get_jwt_identity()
        transactions = Transaction.query.filter_by(user_id=user_id).all()
        transaction_data = [
            {"type": transaction.type, "amount": transaction.amount, "timestamp": transaction.timestamp}
            for transaction in transactions
        ]
        return jsonify(transaction_data), 200
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}")
        return jsonify({"error": "Error fetching transactions"}), 500

@main.route('/loan-page', methods=['GET'])
def get_loan_page():
    try:
        content = {
            "title": "LOAN",
            "fields": ["First Name", "Last Name", "Email Address", "Phone Number", "Required Treatment", "Estimated Cost", "Healthcare Provider"]
        }
        return jsonify(content)
    except Exception as e:
        logger.error(f"Error fetching loan page content: {str(e)}")
        return jsonify({"error": "Error fetching loan page content"}), 500

@main.route('/submit-loan', methods=['POST'])
@csrf.exempt
@jwt_required()
def submit_loan():
    try:
        data = request.get_json()
        errors = validate_required_fields(data, ["first_name", "last_name", "email", "phone_number", "required_treatment", "estimated_cost", "healthcare_provider"])
        if errors:
            return jsonify({"errors": errors}), 400
        
        if not validate_email(data.get('email')):
            return jsonify({"errors": ["Invalid email format"]}), 400

        if not validate_phone_number(data.get('phone_number')):
            return jsonify({"errors": ["Invalid phone number format"]}), 400

        new_loan = LoanApplication(
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            email=data.get('email'),
            phone_number=data.get('phone_number'),
            required_treatment=data.get('required_treatment'),
            estimated_cost=data.get('estimated_cost'),
            healthcare_provider=data.get('healthcare_provider'),
            user_id=get_jwt_identity()
        )
        db.session.add(new_loan)
        db.session.commit()
        return jsonify({"success": "Loan application submitted"}), 200
    except Exception as e:
        logger.error(f"Error submitting loan application: {str(e)}")
        return jsonify({"error": "Error submitting loan application"}), 500

@main.route('/loans', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_loans():
    try:
        user_id = get_jwt_identity()
        loans = LoanApplication.query.filter_by(user_id=user_id).all()
        loan_list = [{"first_name": loan.first_name, "last_name": loan.last_name, "email": loan.email, "phone_number": loan.phone_number, "required_treatment": loan.required_treatment, "estimated_cost": loan.estimated_cost, "healthcare_provider": loan.healthcare_provider} for loan in loans]
        return jsonify(loan_list), 200
    except Exception as e:
        logger.error(f"Error fetching loans: {str(e)}")
        return jsonify({"error": "Error fetching loans"}), 500

# @main.route('/login', methods=['POST'])
# @csrf.exempt
# def login():
#     try:
#         data = request.get_json()
#         user = User.query.filter_by(email=data.get('email')).first()
#         if user and user.check_password(data.get('password')):
#             token = create_access_token(identity=user.id)
#             return jsonify({"token": token}), 200
#         return jsonify({"error": "Invalid credentials"}), 401
#     except Exception as e:
#         logger.error(f"Error logging in: {str(e)}")
#         return jsonify({"error": "Error logging in"}), 500

# @main.route('/register', methods=['POST'])
# @csrf.exempt
# def register():
#     try:
#         data = request.get_json()
#         if not validate_email(data.get('email')):
#             return jsonify({"errors": ["Invalid email format"]}), 400
        
#         user = User(
#             email=data.get('email')
#         )
#         user.set_password(data.get('password'))
#         db.session.add(user)
#         db.session.commit()
#         return jsonify({"success": "User registered"}), 200
#     except Exception as e:
#         logger.error(f"Error registering user: {str(e)}")
#         return jsonify({"error": "Error registering user"}), 500

@main.route('/loan/<int:id>', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_loan(id):
    try:
        user_id = get_jwt_identity()
        loan = LoanApplication.query.filter_by(id=id, user_id=user_id).first()
        if not loan:
            return jsonify({"error": "Loan application not found"}), 404
        loan_data = {
            "id": loan.id,
            "first_name": loan.first_name,
            "last_name": loan.last_name,
            "email": loan.email,
            "phone_number": loan.phone_number,
            "required_treatment": loan.required_treatment,
            "estimated_cost": loan.estimated_cost,
            "healthcare_provider": loan.healthcare_provider,
            "status": loan.status,
            "application_date": loan.application_date
        }
        return jsonify(loan_data), 200
    except Exception as e:
        logger.error(f"Error fetching loan application: {str(e)}")
        return jsonify({"error": "Error fetching loan application"}), 500

@main.route('/loan/<int:id>', methods=['PUT'])
@csrf.exempt
@jwt_required()
def update_loan(id):
    try:
        user_id = get_jwt_identity()
        loan = LoanApplication.query.filter_by(id=id, user_id=user_id).first()
        if not loan:
            return jsonify({"error": "Loan application not found"}), 404

        data = request.get_json()
        loan.first_name = data.get('first_name', loan.first_name)
        loan.last_name = data.get('last_name', loan.last_name)
        loan.email = data.get('email', loan.email)
        loan.phone_number = data.get('phone_number', loan.phone_number)
        loan.required_treatment = data.get('required_treatment', loan.required_treatment)
        loan.estimated_cost = data.get('estimated_cost', loan.estimated_cost)
        loan.healthcare_provider = data.get('healthcare_provider', loan.healthcare_provider)
        
        db.session.commit()
        return jsonify({"success": "Loan application updated"}), 200
    except Exception as e:
        logger.error(f"Error updating loan application: {str(e)}")
        return jsonify({"error": "Error updating loan application"}), 500

@main.route('/loan/<int:id>', methods=['DELETE'])
@csrf.exempt
@jwt_required()
def delete_loan(id):
    try:
        user_id = get_jwt_identity()
        loan = LoanApplication.query.filter_by(id=id, user_id=user_id).first()
        if not loan:
            return jsonify({"error": "Loan application not found"}), 404

        db.session.delete(loan)
        db.session.commit()
        return jsonify({"success": "Loan application deleted"}), 200
    except Exception as e:
        logger.error(f"Error deleting loan application: {str(e)}")
        return jsonify({"error": "Error deleting loan application"}), 500
    
@main.route('/dashboard', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_dashboard_data():
    try:
        user_id = get_jwt_identity()
        savings = Savings.query.filter_by(user_id=user_id).first()
        income = db.session.query(db.func.sum(Income.amount)).filter_by(user_id=user_id).scalar() or 0
        expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=user_id).scalar() or 0

        balance = savings.balance if savings else 0

        return jsonify({
            "balance": balance,
            "income": income,
            "savings": balance,
            "expenses": expenses
        }), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return jsonify({"error": "Error fetching dashboard data"}), 500

@main.route('/finances', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_finances():
    try:
        user_id = get_jwt_identity()
        transactions = Transaction.query.filter_by(user_id=user_id).all()
        finances = [
            {"date": transaction.timestamp, "amount": transaction.amount, "type": transaction.type}
            for transaction in transactions
        ]
        return jsonify({"finances": finances}), 200
    except Exception as e:
        logger.error(f"Error fetching finances: {str(e)}")
        return jsonify({"error": "Error fetching finances"}), 500

@main.route('/expenses/summary', methods=['GET'])
@csrf.exempt
@jwt_required()
def get_expense_summary():
    try:
        user_id = get_jwt_identity()
        daily_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.user_id == user_id,
            db.func.date(Expense.date) == db.func.date(db.func.now())
        ).scalar() or 0

        monthly_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.user_id == user_id,
            db.func.extract('month', Expense.date) == db.func.extract('month', db.func.now())
        ).scalar() or 0

        yearly_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.user_id == user_id,
            db.func.extract('year', Expense.date) == db.func.extract('year', db.func.now())
        ).scalar() or 0

        return jsonify({
            "daily": daily_expenses,
            "monthly": monthly_expenses,
            "yearly": yearly_expenses
        }), 200
    except Exception as e:
        logger.error(f"Error fetching expense summary: {str(e)}")
        return jsonify({"error": "Error fetching expense summary"}), 500

# Suggested additional endpoints:

@main.route('/income', methods=['POST'])
@csrf.exempt
@jwt_required()
def add_income():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        amount = data.get('amount')
        
        if not validate_amount(amount):
            return jsonify({"error": "Invalid amount"}), 400

        income = Income(user_id=user_id, amount=amount)
        db.session.add(income)
        db.session.commit()
        
        return jsonify({"success": "Income added successfully"}), 200
    except Exception as e:
        logger.error(f"Error adding income: {str(e)}")
        return jsonify({"error": "Error adding income"}), 500

@main.route('/expense', methods=['POST'])
@csrf.exempt
@jwt_required()
def add_expense():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        amount = data.get('amount')
        
        if not validate_amount(amount):
            return jsonify({"error": "Invalid amount"}), 400

        expense = Expense(user_id=user_id, amount=amount)
        db.session.add(expense)
        db.session.commit()
        
        return jsonify({"success": "Expense added successfully"}), 200
    except Exception as e:
        logger.error(f"Error adding expense: {str(e)}")
        return jsonify({"error": "Error adding expense"}), 500

@main.route('/contact-info', methods=['GET'])
def contact_info():
    return jsonify({
        "email": "email@gmail.com",
        "phone": "+254712345678"
    })

@main.route('/send-message', methods=['POST'])
# @limiter.limit("5 per hour")
def send_message():
    logger.debug("Received a request to send a message.")
    data = request.get_json()
    logger.debug(f"Request data: {data}")

    errors = validate_contact_form(data)
    if errors:
        logger.debug(f"Validation errors: {errors}")
        return jsonify({"errors": errors}), 400
    
    success, error_message = send_contact_message(data)
    if not success:
        logger.error(f"Failed to send message: {error_message}")
        return jsonify({"error": error_message}), 500
    
    new_message = ContactMessage(name=data['name'], email=data['email'], message=data['message'])
    try:
        db.session.add(new_message)
        db.session.commit()
        logger.debug("Message saved to database successfully.")
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to save message to database."}), 500
    
    return jsonify({"success": "Message sent"}), 200

@main.route('/about-us', methods=['GET'])
def get_about_us():
    try:
        content = {
            "title": "ABOUT US",
            "description": "Healthfin recognizes the burden of healthcare costs. We bridge the gap to affordability by offering flexible and affordable health insurance plans, along with expert advice and personalized support, aiming to provide value with competitive rates and flexible repayment options."
        }
        return jsonify(content)
    except Exception as e:
        logger.error(f"Error fetching about us content: {str(e)}")
        return jsonify({"error": "Error fetching about us content"}), 500

@main.route('/mission', methods=['GET'])
def get_mission():
    try:
        content = {
            "title": "OUR MISSION",
            "description": "To champion well-being by providing accessible, comprehensive health insurance and fostering a culture of preventative care for a healthier and more vibrant future."
        }
        return jsonify(content)
    except Exception as e:
        logger.error(f"Error fetching mission content: {str(e)}")
        return jsonify({"error": "Error fetching mission content"}), 500

@main.route('/vision', methods=['GET'])
def get_vision():
    try:
        content = {
            "title": "OUR VISION",
            "description": "We envision a future where healthy living is accessible to all. By connecting people with affordable and comprehensive health services, we empower individuals to live healthier, more fulfilling lives."
        }
        return jsonify(content)
    except Exception as e:
        logger.error(f"Error fetching vision content: {str(e)}")
        return jsonify({"error": "Error fetching vision content"}), 500

@main.route('/message', methods=['GET'])
def get_message():
    try:
        content = {
            "title": "OUR MESSAGE",
            "description": "Healthfin is a health insurance company built on the foundation of empowering your well-being. We believe health insurance should be more than just a policy; it is the support you need to be an active partner in your journey to a healthier, happier you."
        }
        return jsonify(content)
    except Exception as e:
        logger.error(f"Error fetching message content: {str(e)}")
        return jsonify({"error": "Error fetching message content"}), 500
