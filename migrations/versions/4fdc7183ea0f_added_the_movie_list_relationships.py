"""Added the Movie-List relationships

Revision ID: 4fdc7183ea0f
Revises: 8f07ea6b6802
Create Date: 2024-09-19 15:53:50.535907

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4fdc7183ea0f'
down_revision = '8f07ea6b6802'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('movielist_movie',
    sa.Column('movielist_id', sa.Integer(), nullable=False),
    sa.Column('movie_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['movie_id'], ['movie.id'], ),
    sa.ForeignKeyConstraint(['movielist_id'], ['movie_list.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('movielist_movie')
    # ### end Alembic commands ###
