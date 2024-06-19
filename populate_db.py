from app import create_app, db
from app.models import User, LoanApplication, Savings, SavingPlan, Transaction, ContactForm
from datetime import datetime

def populate_db():
    app = create_app()
    with app.app_context():
        db.create_all()

        # Create test users
        users = [
            {
                "first_name": "Brian",
                "last_name": "Eugene",
                "email": "brianeugene851@gmail.com",
                "phone_number": "0798925396",
                "password": "password124?",
                "email_verified": True,
                "is_blocked": False,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            },
            {
                "first_name": "Brian",
                "last_name": "Ugene",
                "email": "brianugene851@gmail.com",
                "phone_number": "1234567890",
                "password": "password1213?",
                "email_verified": False,
                "is_blocked": False,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            },
            {
                "first_name": "Test",
                "last_name": "User1",
                "email": "testuser1@example.com",
                "phone_number": "0987654321",
                "password": "testpassword1",
                "email_verified": True,
                "is_blocked": False,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            },
            {
                "first_name": "Test",
                "last_name": "User2",
                "email": "testuser2@example.com",
                "phone_number": "1122334455",
                "password": "testpassword2",
                "email_verified": True,
                "is_blocked": True,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            },
            {
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "1010101010",
                "password": "password123?",
                "email_verified": False,
                "is_blocked": False,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            },
            {
                "first_name": "Jane",
                "last_name": "Smith",
                "email": "janesmith@example.com",
                "phone_number": "2020202020",
                "password": "mypassword456!",
                "email_verified": True,
                "is_blocked": False,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "session_start_time": None
            }
        ]

        for user_data in users:
            user = User(
                first_name=user_data["first_name"],
                last_name=user_data["last_name"],
                email=user_data["email"],
                phone_number=user_data["phone_number"],
                email_verified=user_data["email_verified"],
                is_blocked=user_data["is_blocked"],
                created_at=user_data["created_at"],
                last_login=user_data["last_login"],
                session_start_time=user_data["session_start_time"]
            )
            user.set_password(user_data["password"])  # Use set_password method
            db.session.add(user)

        # Create test savings
        savings = [
            {
                "user_id": 1,
                "balance": 1000.0
            },
            {
                "user_id": 2,
                "balance": 2000.0
            },
            {
                "user_id": 3,
                "balance": 3000.0
            }
        ]

        for saving_data in savings:
            saving = Savings(
                user_id=saving_data["user_id"],
                balance=saving_data["balance"]
            )
            db.session.add(saving)

        # Create test saving plans
        saving_plans = [
            {
                "name": "Plan A",
                "description": "Basic saving plan"
            },
            {
                "name": "Plan B",
                "description": "Intermediate saving plan"
            },
            {
                "name": "Plan C",
                "description": "Advanced saving plan"
            }
        ]

        for plan_data in saving_plans:
            plan = SavingPlan(
                name=plan_data["name"],
                description=plan_data["description"]
            )
            db.session.add(plan)

        # Create test transactions
        transactions = [
            {
                "user_id": 1,
                "type": "deposit",
                "amount": 500.0,
                "timestamp": datetime.utcnow()
            },
            {
                "user_id": 2,
                "type": "withdraw",
                "amount": 100.0,
                "timestamp": datetime.utcnow()
            },
            {
                "user_id": 3,
                "type": "deposit",
                "amount": 300.0,
                "timestamp": datetime.utcnow()
            }
        ]

        for transaction_data in transactions:
            transaction = Transaction(
                user_id=transaction_data["user_id"],
                type=transaction_data["type"],
                amount=transaction_data["amount"],
                timestamp=transaction_data["timestamp"]
            )
            db.session.add(transaction)

        # Create test loan applications
        loan_applications = [
            {
                "user_id": 1,
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe@example.com",
                "phone_number": "1010101010",
                "required_treatment": "Heart surgery",
                "estimated_cost": 25000.0,
                "healthcare_provider": "City Hospital",
                "status": "pending",
                "application_date": datetime.utcnow()
            },
            {
                "user_id": 2,
                "first_name": "Jane",
                "last_name": "Smith",
                "email": "janesmith@example.com",
                "phone_number": "2020202020",
                "required_treatment": "Dental implants",
                "estimated_cost": 5000.0,
                "healthcare_provider": "Dental Care Clinic",
                "status": "approved",
                "application_date": datetime.utcnow()
            }
        ]

        for loan_data in loan_applications:
            loan = LoanApplication(
                user_id=loan_data["user_id"],
                first_name=loan_data["first_name"],
                last_name=loan_data["last_name"],
                email=loan_data["email"],
                phone_number=loan_data["phone_number"],
                required_treatment=loan_data["required_treatment"],
                estimated_cost=loan_data["estimated_cost"],
                healthcare_provider=loan_data["healthcare_provider"],
                status=loan_data["status"],
                application_date=loan_data["application_date"]
            )
            db.session.add(loan)

        # Create test contact form submissions
        contacts = [
            {
                "name": "Alice",
                "email": "alice@example.com",
                "message": "I need help with my account."
            },
            {
                "name": "Bob",
                "email": "bob@example.com",
                "message": "Can you provide more details about your savings plans?"
            }
        ]

        for contact_data in contacts:
            contact = ContactForm(
                name=contact_data["name"],
                email=contact_data["email"],
                message=contact_data["message"]
            )
            db.session.add(contact)

        db.session.commit()
        print("Database populated with test data.")

if __name__ == "__main__":
    populate_db()
