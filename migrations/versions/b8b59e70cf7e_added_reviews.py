"""Added reviews.

Revision ID: b8b59e70cf7e
Revises: 
Create Date: 2024-09-12 17:00:46.936166

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b8b59e70cf7e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('review',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('description', sa.String(length=256), nullable=False),
    sa.Column('rating', sa.Integer(), nullable=False),
    sa.Column('reviewer_id', sa.Integer(), nullable=False),
    sa.Column('reviewed_movie_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['reviewed_movie_id'], ['movie.id'], ),
    sa.ForeignKeyConstraint(['reviewer_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('role',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('role',
               existing_type=sa.INTEGER(),
               nullable=True)

    op.drop_table('review')
    # ### end Alembic commands ###
