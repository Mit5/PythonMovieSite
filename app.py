from flask import Flask, render_template, url_for, redirect, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user,LoginManager,login_required,logout_user,current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_reuploads import UploadSet, IMAGES, configure_uploads
from wtforms import StringField, PasswordField, SubmitField, EmailField, FileField, IntegerField, SelectField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from wtforms_sqlalchemy.fields import QuerySelectField
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import uuid as uuid
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
UPLOADED_PHOTOS_DEST = 'static/photos'
app.config['UPLOADED_PHOTOS_DEST'] = UPLOADED_PHOTOS_DEST
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)

db = SQLAlchemy(app)
migrate = Migrate(app,db)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), nullable=False, unique =True)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.Integer, nullable=False)
    reviews = db.relationship('Review',backref='reviewer')
    movie_lists = db.relationship('MovieList', backref='creator')

movielist_movie = db.Table('movielist_movie',
        db.Column('movielist_id',db.Integer, db.ForeignKey('movie_list.id'),nullable=False),
        db.Column('movie_id',db.Integer, db.ForeignKey('movie.id'),nullable=False)
)

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(256))
    duration = db.Column(db.Integer)
    director = db.Column(db.String(50))
    photo = db.Column(db.String())
    reviews = db.relationship('Review',backref='reviewed_movie')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key= True, autoincrement=True)
    description = db.Column(db.String(256),nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
    reviewed_movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'),nullable=False)

class MovieList(db.Model):
    id = db.Column(db.Integer, primary_key= True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
    movies = db.relationship('Movie', secondary = movielist_movie, backref='included_lists')

class RegistrationForm(FlaskForm):
    email = EmailField(validators=[InputRequired(),Email(),Length(min=4,max=50)], render_kw={'placeholder': 'Email'})
    name = StringField(validators=[InputRequired(), Length(min=4,max=50)], render_kw={'placeholder':'Name'})
    password = PasswordField(validators=[InputRequired(),Length(min=3,max=20)], render_kw={'placeholder':'Password'})

    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()

        if existing_user_email:
            raise ValidationError("Email already registered! Please choose a different one.")
        
class LoginForm(FlaskForm):
    email = EmailField(validators=[InputRequired(),Email(),Length(min=4,max=50)], render_kw={'placeholder': 'Email'})
    password = PasswordField(validators=[InputRequired(),Length(min=3,max=20)], render_kw={'placeholder':'Password'})

    submit = SubmitField("Login")

class ChangeForm(FlaskForm):
    email = EmailField(validators=[Length(min=0,max=50)], render_kw={'placeholder': 'Email'})
    name = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Name'})
    password = PasswordField(validators=[Length(min=0,max=20)], render_kw={'placeholder':'New Password'})
    current_password = PasswordField(validators=[InputRequired(),Length(min=3,max=20)], render_kw={'placeholder':'Current Password'})

    submit = SubmitField("Change")

    def validate_email(self, email):
        if not email == "":
            existing_user_email = User.query.filter_by(email=email.data).first()

            if existing_user_email:
                raise ValidationError("Email already registered! Please choose a different one.")

class AddMovieForm(FlaskForm):
    name = StringField(validators=[InputRequired(),Length(min=0,max=50)], render_kw={'placeholder':'Name'})
    description = StringField(validators=[Length(min=0,max=256)], render_kw={'placeholder':'Name'})
    duration = IntegerField(render_kw={'placeholder':'Duration'})
    director = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Director'})
    photo = FileField('Picture')
    submit = SubmitField('Add Movie')

class EditMovieForm(FlaskForm):
    name = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Name'})
    description = StringField(validators=[Length(min=0,max=256)], render_kw={'placeholder':'Name'})
    duration = IntegerField(render_kw={'placeholder':'Duration'})
    director = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Director'})
    photo = FileField('Picture')
    submit = SubmitField('Edit Movie')

class MovieReviewForm(FlaskForm):
    description = StringField(validators=[InputRequired(),Length(min=10,max=256)], render_kw={'placeholder':'Review'})
    rating = SelectField('Select score', choices=[(1,'(1) Unwatchable'),(2,'(2) Awful'),(3,'(3) Very Bad'),
                                                  (4,'(4) Bad'),(5,'(5) Mediocre'),(6,'(6) Fine'),
                                                  (7,'(7) Good'),(8,'(8) Great'),
                                                  (9,'(9) Amazing'),(10,'(10) Masterpiece')], validators=[InputRequired()])
    submit = SubmitField('Add Review')

class EditReviewForm(FlaskForm):
    description = StringField(validators=[InputRequired(),Length(min=10,max=256)], render_kw={'placeholder':'Review'})
    rating = SelectField('Select score', choices=[(1,'(1) Unwatchable'),(2,'(2) Awful'),(3,'(3) Very Bad'),
                                                  (4,'(4) Bad'),(5,'(5) Mediocre'),(6,'(6) Fine'),
                                                  (7,'(7) Good'),(8,'(8) Great'),
                                                  (9,'(9) Amazing'),(10,'(10) Masterpiece')], validators=[InputRequired()])
    submit = SubmitField('Edit Review')

def list_choices():
    return MovieList.query.filter_by(creator_id = current_user.id)

class ListAddMovieForm(FlaskForm):
    lists = QuerySelectField(u'My Lists', validators=[InputRequired()], query_factory=list_choices, get_label='name')
    submit = SubmitField('Add Movie to List')

class ListMoveMovieForm(FlaskForm):
    lists = QuerySelectField(u'My Lists', validators=[InputRequired()], query_factory=list_choices, get_label='name')
    movie_id = HiddenField()
    submit = SubmitField('Move Movie to List')

class CreateListForm(FlaskForm):
    name = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Name'})
    submit = SubmitField('Create List')

class ListRenameForm(FlaskForm):
    name = StringField(validators=[Length(min=0,max=50)], render_kw={'placeholder':'Name'})
    submit = SubmitField('Rename') 

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('movies'))
    return render_template('home.html')

@app.route('/users')
@login_required
def users():
    user = User.query.get(current_user.id)
    users = User.query.all()
    if user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    return render_template('users.html',user=user, users = users)

@app.route('/users/view/<int:id>')
@login_required
def users_view(id:int):
    user = User.query.get(id)
    reviews = Review.query.filter_by(reviewer_id = id)
    lists = MovieList.query.filter_by(creator_id = id)
    return render_template('users_view.html',user=current_user, viewing_user=user, reviews=reviews,reviews_count=len(reviews.all()), lists=lists)

@app.route('/users/delete/<int:curr_id>')
@login_required
def user_delete(curr_id):
    curr_user = User.query.get(current_user.id)
    employee = User.query.get(curr_id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    if not employee:
        flash('Wrong id.')
    User.query.filter_by(id=curr_id).delete()
    db.session.commit()
    flash('User deleted.')
    return redirect(url_for('users'))


@app.route('/users/promote/<int:id>')
@login_required
def user_promote(id):
    curr_user = User.query.get(current_user.id)
    employee = User.query.get(id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    if not employee:
        flash('Wrong id.')
    employee.role = 1
    db.session.commit()
    flash('User promoted to admin.')
    return redirect(url_for('users'))

@app.route('/users/demote/<int:id>')
@login_required
def user_demote(id):
    curr_user = User.query.get(current_user.id)
    employee = User.query.get(id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    if not employee:
        flash('Wrong id.')
    employee.role = 0
    db.session.commit()
    flash('User demoted.')
    return redirect(url_for('users'))

@app.route('/list_add_movie/<int:list_id>/<int:movie_id>', methods = ['GET','POST'])
@login_required
def list_add_movie(list_id:int,movie_id:int):
    movielist = MovieList.query.get(list_id)
    if (current_user.id != movielist.creator_id):
        flash('Only the creator can add movies to a list.')
        return redirect(url_for('movies_view',id=movie_id))
    movie = Movie.query.get(movie_id)
    if not movie in movielist.movies:
        movielist.movies.append(movie)
        db.session.commit()
        flash(f'{movie.name} successfully added to {movielist.name}.')
    else:
        flash(f'{movie.name} already in {movielist.name}.')
    return redirect(url_for('movies_view',id=movie_id))

@app.route('/list_remove_movie/<int:list_id>/<int:movie_id>')
@login_required
def list_remove_movie(list_id:int,movie_id:int):
    movielist = MovieList.query.get(list_id)
    if (current_user.id != movielist.creator_id):
        flash('Only the creator can remove movies from a list.')
        return redirect(url_for('home'))
    movie = Movie.query.get(movie_id)
    movielist.movies.remove(movie)
    db.session.commit()
    flash(f'{movie.name} successfully removed from {movielist.name}.')
    return redirect(url_for('lists_view',id=list_id))

@app.route('/list_move_movie/<int:list_from_id>/<int:list_to_id>/<int:movie_id>')
@login_required
def list_move_movie(list_from_id:int, list_to_id:int,movie_id:int):
    listfrom = MovieList.query.get(list_from_id)
    listto = MovieList.query.get(list_to_id)
    if (current_user.id != listfrom.creator_id or current_user.id != listto.creator_id):
        flash('Only the creator can move movies from a list.')
        return redirect(url_for('home'))
    movie = Movie.query.get(movie_id)
    if not movie in listto.movies:
        listfrom.movies.remove(movie)
        listto.movies.append(movie)
        db.session.commit()
        flash(f'{movie.name} successfully moved to {listto.name}.')
    else:
        flash(f'{movie.name} already in {listto.name}.')
    return redirect(url_for('lists_view',id=list_from_id))

@app.route('/lists/delete/<int:id>')
@login_required
def lists_delete(id:int):
    movielist = MovieList.query.get(id)
    if current_user.id != movielist.creator_id:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    if not movielist:
        flash('Wrong id.')
    MovieList.query.filter_by(id=id).delete()
    db.session.commit()
    flash(f'{movielist.name} successfully deleted.')
    return redirect(url_for('my_lists'))
    

@app.route('/lists/copy/<int:id>')
@login_required
def lists_copy(id:int):
    movielist = MovieList.query.get(id)
    if movielist.creator_id == current_user.id:
        flash(f'You cannot copy your own lists!')
        return redirect(url_for('lists_view',id=id))
    newmovielist = MovieList(name=movielist.name,creator_id = current_user.id,movies=movielist.movies)
    db.session.add(newmovielist)
    db.session.commit()
    flash(f'Copied {movielist.name} successfully')
    return redirect(url_for('lists_view',id=id))

@app.route('/movies')
def movies():
    movies = Movie.query.all()
    return render_template('movies/movies.html',user=current_user,movies=movies)

@app.route('/movies/add', methods = ['GET','POST'])
@login_required
def movies_add():
    curr_user = User.query.get(current_user.id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    
    form = AddMovieForm()
    if form.validate_on_submit():
        filename = secure_filename(form.photo.data.filename)
        photo_name = str(uuid.uuid1()) + '_' + filename
        filepath = os.path.join(app.config['UPLOADED_PHOTOS_DEST'],photo_name)
        form.photo.data.save(filepath)
        new_movie = Movie(name = form.name.data, 
                        description = form.description.data, 
                        duration = form.duration.data, 
                        director = form.director.data, 
                        photo = filepath)
        db.session.add(new_movie)
        db.session.commit()
        flash('Movie successfully added.')
        return redirect(url_for('movies'))
    
    return render_template('movies/movies_add.html',user=current_user,form = form)

@app.route('/movies/view/<int:id>', methods=['GET','POST'])
def movies_view(id:int):
    form = ListAddMovieForm()
    if form.validate_on_submit():
        return redirect(url_for('list_add_movie',list_id = form.lists.data.id, movie_id = id))
    movie = Movie.query.get(id)
    movie.photo = movie.photo
    reviews = Review.query.filter_by(reviewed_movie_id = id)
    return render_template('movies/movies_view.html',user=current_user,movie=movie,reviews = reviews, reviews_count = len(reviews.all()),form=form)

@app.route('/movies/delete/<int:id>')
@login_required
def movies_delete(id):
    curr_user = User.query.get(current_user.id)
    movie = Movie.query.get(id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    if not movie:
        flash('Wrong id.')
    os.remove(movie.photo)
    Movie.query.filter_by(id=id).delete()
    db.session.commit()
    flash('Movie deleted.')
    return redirect(url_for('movies'))

@app.route('/movies/edit/<int:id>' , methods = ['GET','POST'])
@login_required
def movies_edit(id):
    curr_user = User.query.get(current_user.id)
    if curr_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    
    movie = Movie.query.get(id)
    form = EditMovieForm()

    if form.validate_on_submit():
        if form.photo.data:
            os.remove(movie.photo)
            filename = secure_filename(form.photo.data.filename)
            photo_name = str(uuid.uuid1()) + '_' + filename
            filepath = os.path.join(app.config['UPLOADED_PHOTOS_DEST'],photo_name)
            form.photo.data.save(filepath)
            movie.photo = filepath
        movie.name = form.name.data
        movie.description = form.description.data
        movie.duration = form.duration.data 
        movie.director = form.director.data 
        db.session.add(movie)
        db.session.commit()
        flash('Movie successfully edited.')
        return redirect(url_for('movies'))
    
    form.name.data = movie.name
    form.description.data = movie.description
    form.duration.data = movie.duration
    form.director.data = movie.director
    movie.photo = movie.photo
    
    return render_template('movies/movies_edit.html',user=current_user,form = form, movie=movie)

@app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
    user = User.query.get(current_user.id)
    
    form = ChangeForm()
    updates = []
    if form.validate_on_submit():
        if not bcrypt.check_password_hash(user.password,form.current_password.data):
                flash('Incorrent password!')
                return redirect(url_for('dashboard'))
        if not form.name.data == "" or not form.name.data == user.name:
            user.name = form.name.data
            updates.append('name')
        if not form.password.data == "":
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            user.password = hashed_password
            updates.append('password')
        # user.name = form.name.data
        # hashed_password = bcrypt.generate_password_hash(form.password.data)
        # user.password = hashed_password
        db.session.add(user)
        db.session.commit()
        if len(updates) == 0:
            flash(f'No updates were made!')
        elif len(updates) == 1:
            flash(f'Updated {updates[0]} successfully!')
        else:
            flash(f'Updated {','.join(updates[:-1])} and {updates[-1]} successfully!')
        return redirect(url_for('dashboard'))
    form.email.data = user.email
    form.name.data = user.name
    return render_template('dashboard.html',form=form,user=user)


@app.route('/movies/review/<int:movie_id>', methods = ['GET','POST'])
@login_required
def movies_review(movie_id):
    user = User.query.get(current_user.id)
    movie = Movie.query.get(movie_id)
    form = MovieReviewForm()
    if form.validate_on_submit():
        new_review = Review(description=form.description.data,
                            rating = form.rating.data,
                            reviewer_id = current_user.id,
                            reviewed_movie_id = movie_id)
        db.session.add(new_review)
        db.session.commit()
        flash('Review successfully added.')
        return redirect(url_for('movies'))
    return render_template('movies/movie_review.html',form=form,user=user,movie=movie)

@app.route('/my_reviews',methods = ['GET','POST'])
@login_required
def my_reviews():
    user = User.query.get(current_user.id)
    reviews = Review.query.filter_by(reviewer_id = current_user.id)
    return render_template('reviews/my_reviews.html',user=user,reviews=reviews,reviews_count=len(reviews.all()))

@app.route('/reviews/view/<int:id>',methods = ['GET','POST'])
@login_required
def reviews_view(id):
    review = Review.query.get(id)
    review.reviewed_movie.photo = review.reviewed_movie.photo
    return render_template('reviews/reviews_view.html',user=current_user,review=review)

@app.route('/reviews/edit/<int:id>', methods = ['GET','POST'])
@login_required
def reviews_edit(id):
    review = Review.query.get(id)
    if not review.reviewer.id == current_user.id:
        flash('You do not have permission to edin this review.')
        return redirect(url_for('my_reviews'))
    form = EditReviewForm()
    if form.validate_on_submit():
        review.description = form.description.data
        review.rating = form.rating.data
        db.session.add(review)
        db.session.commit()
        flash('Review successfully updated.')
        return redirect(url_for('reviews_view',id=review.id))
    form.description.data = review.description
    form.rating.data = review.rating
    return render_template('reviews/reviews_edit.html',user=current_user,form=form,review=review)
    
@app.route('/my_lists')
@login_required
def my_lists():
    user_id = current_user.id
    lists = MovieList.query.filter_by(creator_id=user_id)
    return render_template('lists/my_lists.html', lists=lists,user=current_user)

@app.route('/lists/create',methods=['GET','POST'])
@login_required
def lists_create():
    form = CreateListForm()
    if form.validate_on_submit():
        new_list = MovieList(name=form.name.data,creator_id=current_user.id)
        db.session.add(new_list)
        db.session.commit()
        flash('List successfully created.')
        return redirect(url_for('lists_view',id=new_list.id))
    return render_template('lists/lists_create.html', form=form, user=current_user)

@app.route('/lists/view/<int:id>', methods=['GET','POST'])
@login_required
def lists_view(id:int):
    list = MovieList.query.get(id)
    form = ListMoveMovieForm()
    rename_form = ListRenameForm()
    if form.validate_on_submit():
        return redirect(url_for('list_move_movie',list_from_id = id,list_to_id = form.lists.data.id, movie_id = int(form.movie_id.data)))
    if rename_form.validate_on_submit():
        old_name = list.name
        list.name = rename_form.name.data
        db.session.add(list)
        db.session.commit()
        flash(f'{old_name} successfully renamed to {list.name}.')
        return redirect(url_for('lists_view',id=id))

    return render_template('lists/lists_view.html', list=list,user=current_user,form=form,rename_form=rename_form)
#list_from_id:int, list_to_id:int,movie_id:int)

@app.route('/login', methods = ['GET','POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            
    return render_template('login.html', form = form)

@app.route('/register/create_default_lists/<int:user_id>',methods = ['GET','POST'])
@login_required
def createDefaultLists(user_id:int):
    if current_user.role != 1:
        flash('Only admins can access this page.')
        return redirect(url_for('home'))
    lists = MovieList.query.filter_by(creator_id=user_id)
    if len(lists.all()) > 0:
        flash('Lists already created.')
        return redirect(url_for('home'))
    favourites = MovieList(name='Favourites',creator_id = user_id)
    watched = MovieList(name='Watched', creator_id = user_id)
    to_watch = MovieList(name='To Watch', creator_id = user_id)
    db.session.add(favourites)
    db.session.add(watched)
    db.session.add(to_watch)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/register', methods = ['GET','POST'])
def register():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, name=form.name.data, password=hashed_password,role=0)
        db.session.add(new_user)
        db.session.commit()
        flash('Thank you for registering!')
        favourites = MovieList(name='Favourites',creator_id = new_user.id)
        watched = MovieList(name='Watched', creator_id = new_user.id)
        to_watch = MovieList(name='To Watch', creator_id = new_user.id)
        db.session.add(favourites)
        db.session.add(watched)
        db.session.add(to_watch)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

@app.route('/logout', methods = ['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__=='__main__':
    app.run(debug=True)
