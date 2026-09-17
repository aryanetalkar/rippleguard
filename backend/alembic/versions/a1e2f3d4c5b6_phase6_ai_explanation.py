"""phase6_ai_explanation

Revision ID: a1e2f3d4c5b6
Revises: fb81a1083406
Create Date: 2026-09-17 21:18:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1e2f3d4c5b6'
down_revision: Union[str, Sequence[str], None] = 'fb81a1083406'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'risk_explanations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('risk_result_id', sa.Integer(), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('prompt_version', sa.String(length=50), nullable=False),
        sa.Column('evidence_version', sa.String(length=50), nullable=False),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('why_priority', sa.Text(), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('key_factors', sa.JSON(), nullable=True),
        sa.Column('mitigation_guidance', sa.Text(), nullable=True),
        sa.Column('limitations', sa.JSON(), nullable=True),
        sa.Column('evidence_ids', sa.JSON(), nullable=True),
        sa.Column('input_evidence', sa.JSON(), nullable=True),
        sa.Column('generated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('failed_reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['risk_result_id'], ['risk_results.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_risk_explanations_risk_result_id'), 'risk_explanations', ['risk_result_id'], unique=False)
    op.create_index(op.f('ix_risk_explanations_evidence_hash'), 'risk_explanations', ['evidence_hash'], unique=False)
    op.create_index(op.f('ix_risk_explanations_status'), 'risk_explanations', ['status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_risk_explanations_status'), table_name='risk_explanations')
    op.drop_index(op.f('ix_risk_explanations_evidence_hash'), table_name='risk_explanations')
    op.drop_index(op.f('ix_risk_explanations_risk_result_id'), table_name='risk_explanations')
    op.drop_table('risk_explanations')
