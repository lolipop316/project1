# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import csv, io

# -------------------------
# App Setup
# -------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------------
# Models
# -------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='Other')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.String(500))
    recurring_id = db.Column(db.Integer, db.ForeignKey('recurring_expense.id'))
    user = db.relationship('User', backref=db.backref('expenses', lazy=True))

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='Salary')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.String(500))
    user = db.relationship('User', backref=db.backref('income', lazy=True))

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user = db.relationship('User', backref=db.backref('budgets', lazy=True))

class RecurringExpense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    frequency_days = db.Column(db.Integer, default=30)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('recurring_expenses', lazy=True))
    expenses = db.relationship('Expense', backref='recurring_expense', lazy=True)

# -------------------------
# Login Manager
# -------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# Routes
# -------------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

# -------------------------
# Dashboard
# -------------------------
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    # Handle new expense
    if request.method=='POST' and 'expense_submit' in request.form:
        try:
            amount = float(request.form['amount'])
            expense = Expense(
                user_id=current_user.id,
                description=request.form['description'],
                amount=amount,
                category=request.form['category'],
                notes=request.form.get('notes','')
            )
            db.session.add(expense)
            db.session.commit()
            flash('Expense added!', 'success')
        except ValueError:
            flash('Invalid amount.', 'danger')
        return redirect(url_for('dashboard'))

    # Handle new income
    if request.method=='POST' and 'income_submit' in request.form:
        try:
            amount = float(request.form['amount_income'])
            income = Income(
                user_id=current_user.id,
                description=request.form['description_income'],
                amount=amount,
                category=request.form['category_income'],
                notes=request.form.get('notes_income','')
            )
            db.session.add(income)
            db.session.commit()
            flash('Income added!', 'success')
        except ValueError:
            flash('Invalid amount.', 'danger')
        return redirect(url_for('dashboard'))

    # Query data
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
    income = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).all()
    budgets = {b.category: b.amount for b in Budget.query.filter_by(user_id=current_user.id).all()}

    total_exp = sum(e.amount for e in expenses)
    total_inc = sum(i.amount for i in income)
    balance = total_inc - total_exp

    # Expenses per category
    category_totals = {}
    for e in expenses:
        category_totals[e.category] = category_totals.get(e.category,0) + e.amount
    chart_labels = list(category_totals.keys())
    chart_values = [round(category_totals[c],2) for c in chart_labels]

    # Expenses vs Budget
    budget_labels = list(budgets.keys())
    budget_values = [budgets[c] for c in budget_labels]
    budget_exp_values = [category_totals.get(c,0) for c in budget_labels]

    # Income vs Expenses over time
    expenses_by_date = {}
    for e in expenses:
        d = e.date.strftime("%Y-%m-%d")
        expenses_by_date[d] = expenses_by_date.get(d,0) + e.amount
    income_by_date = {}
    for i in income:
        d = i.date.strftime("%Y-%m-%d")
        income_by_date[d] = income_by_date.get(d,0) + i.amount
    all_dates = sorted(set(list(expenses_by_date.keys())+list(income_by_date.keys())))
    line_exp = [expenses_by_date.get(d,0) for d in all_dates]
    line_inc = [income_by_date.get(d,0) for d in all_dates]

    return render_template('dashboard.html',
                           expenses=expenses,
                           income=income,
                           total_expenses=total_exp,
                           total_income=total_inc,
                           balance=balance,
                           chart_labels=chart_labels,
                           chart_values=chart_values,
                           budget_labels=budget_labels,
                           budget_exp_values=budget_exp_values,
                           budget_values=budget_values,
                           line_labels=all_dates,
                           line_exp=line_exp,
                           line_inc=line_inc,
                           budgets=budgets)

# -------------------------
# Recurring Expenses
# -------------------------
@app.route('/add_recurring_expense', methods=['POST'])
@login_required
def add_recurring_expense():
    try:
        amount = float(request.form['amount'])
        freq = int(request.form['frequency_days'])
        rec = RecurringExpense(
            user_id=current_user.id,
            description=request.form['description'],
            amount=amount,
            category=request.form['category'],
            frequency_days=freq,
            start_date=datetime.utcnow()
        )
        db.session.add(rec)
        db.session.commit()
        flash('Recurring expense added!', 'success')
    except ValueError:
        flash('Invalid input!', 'danger')
    return redirect(url_for('dashboard'))

# -------------------------
# Budgets
# -------------------------
@app.route('/set_budget', methods=['POST'])
@login_required
def set_budget():
    try:
        amount = float(request.form['amount'])
        category = request.form['category']
        budget = Budget.query.filter_by(user_id=current_user.id, category=category).first()
        if budget:
            budget.amount = amount
        else:
            budget = Budget(user_id=current_user.id, category=category, amount=amount)
            db.session.add(budget)
        db.session.commit()
        flash(f'Budget for {category} set to ${amount}', 'success')
    except ValueError:
        flash('Invalid amount', 'danger')
    return redirect(url_for('dashboard'))

# -------------------------
# Edit/Delete Expenses
# -------------------------
@app.route('/edit_expense/<int:expense_id>', methods=['GET','POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('Cannot edit this expense', 'danger')
        return redirect(url_for('dashboard'))
    if request.method=='POST':
        expense.description = request.form['description']
        expense.category = request.form['category']
        expense.notes = request.form.get('notes','')
        try:
            expense.amount = float(request.form['amount'])
        except ValueError:
            flash('Invalid amount', 'danger')
            return redirect(url_for('dashboard'))
        db.session.commit()
        flash('Expense updated', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_expense.html', expense=expense)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('Cannot delete this expense', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted', 'info')
    return redirect(url_for('dashboard'))

# -------------------------
# Export CSV
# -------------------------
@app.route('/export_csv')
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Type','Description','Amount','Category','Date','Notes'])
    for e in Expense.query.filter_by(user_id=current_user.id).all():
        writer.writerow(['Expense', e.description, e.amount, e.category, e.date, e.notes])
    for i in Income.query.filter_by(user_id=current_user.id).all():
        writer.writerow(['Income', i.description, i.amount, i.category, i.date, i.notes])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='finance_data.csv')

# -------------------------
# Run App
# -------------------------
if __name__=='__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
