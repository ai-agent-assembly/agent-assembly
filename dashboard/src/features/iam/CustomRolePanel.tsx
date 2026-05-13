import { BUILTIN_ROLE_CATALOGUE, IAM_CUSTOM_ROLES_COPY } from './copy'
import { LockedFeatureCard } from './LockedFeatureCard'
import './CustomRolePanel.css'

export function CustomRolePanel() {
  return (
    <section className="iam-custom-roles" data-testid="iam-custom-roles">
      <header className="iam-custom-roles__header">
        <h3 className="iam-custom-roles__title">{IAM_CUSTOM_ROLES_COPY.title}</h3>
        <p className="iam-custom-roles__sub">{IAM_CUSTOM_ROLES_COPY.description}</p>
      </header>

      <LockedFeatureCard
        testId="custom-roles-locked"
        title="Custom roles are part of Agent Assembly Cloud"
        body={IAM_CUSTOM_ROLES_COPY.lockedBody}
        cta={
          <a
            href={IAM_CUSTOM_ROLES_COPY.upgradeUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="iam-custom-roles__cta"
            data-testid="upgrade-cta"
          >
            {IAM_CUSTOM_ROLES_COPY.upgradeCta} →
          </a>
        }
      />

      <ul className="iam-custom-roles__catalogue" data-testid="builtin-role-list">
        {BUILTIN_ROLE_CATALOGUE.map((role) => (
          <li key={role.id} className="iam-custom-roles__role" data-testid={`builtin-role-${role.id}`}>
            <code className="iam-custom-roles__role-id">{role.label}</code>
            <span className="iam-custom-roles__role-desc">{role.description}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}
