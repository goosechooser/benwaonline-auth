"""empty message

Revision ID: e63fd6a7078b
Revises: 0fbee2fad725
Create Date: 2018-03-29 02:47:55.961205

"""
from alembic import op
import sqlalchemy_utils
import sqlalchemy as sa



# revision identifiers, used by Alembic.
revision = 'e63fd6a7078b'
down_revision = '0fbee2fad725'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('client', sa.Column('allowed_scopes', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('client', 'allowed_scopes')
    # ### end Alembic commands ###
