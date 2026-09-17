# Matriz de permissões — Assessment read-only

Esta matriz é a proposta inicial para o piloto. O princípio é conceder acesso
somente de leitura no menor escopo possível e adicionar módulos apenas quando
forem executados.

| Módulo | API/fonte | Permissão ou role sugerida | Escopo | Observação |
|---|---|---|---|---|
| Inventário Azure | Azure Resource Graph | `Reader` | Management Group ou subscriptions do assessment | Consulta recursos e propriedades expostas pelo ARG; não altera recursos |
| Hierarquia e tags | Azure Resource Graph | `Reader` | Management Group ou subscriptions | Management Group exige que o principal tenha visibilidade nesse escopo |
| RBAC Azure | Azure Resource Manager | `Reader` | Management Group ou subscriptions | Para ler atribuições e escopos; não concede `Role Based Access Control Administrator` |
| Azure Policy | Policy Insights | `Reader` | Management Group ou subscriptions | Consulta estados de conformidade; remediação fica fora do escopo |
| Advisor / retirement | Advisor e Service Health | `Reader` + permissões específicas do serviço, se exigidas | Subscriptions | A cobertura de impacto depende do serviço e dos dados publicados |
| Custos | Cost Management | `Cost Management Reader` | Billing scope, management group ou subscription | Necessário para detalhamento de custo; sem `Contributor` |
| Lifecycle | Advisor / Service Health | `Reader` | Subscription | Retirement pode depender de metadados publicados pelo serviço |
| Identidade | Microsoft Graph | `User.Read.All` | Tenant | Leitura de usuários; validar consentimento administrativo |
| MFA | Microsoft Graph | `UserAuthenticationMethod.Read.All` | Tenant | Métodos registrados; dados devem permanecer no tenant e ser minimizados |
| Registro de MFA em lote | Microsoft Graph Reports | `Reports.Read.All` | Tenant | Endpoint `userRegistrationDetails`; preferir esta consulta a N chamadas por usuário |
| Conditional Access | Microsoft Graph | `Policy.Read.All` | Tenant | Leitura de políticas; não inclui `Policy.ReadWrite.ConditionalAccess` |
| Sign-in e risco | Microsoft Graph | `AuditLog.Read.All`, `IdentityRiskyUser.Read.All` | Tenant | Pode depender de licença e retenção; a janela de sign-in é limitada e a indisponibilidade vira `not_available` |
| Funções privilegiadas | Microsoft Graph | `RoleManagement.Read.Directory`, `Directory.Read.All` | Tenant | Identifica membros de funções privilegiadas para calcular MFA de administradores; endpoint opcional |
| Grupos e convidados | Microsoft Graph | `Group.Read.All`, `User.Read.All` | Tenant | Preferir coleta mínima e mascarar na camada executiva |
| Secure Score | Microsoft Graph | `SecurityEvents.Read.All` | Tenant | Validar disponibilidade e escopo efetivo do endpoint |
| Defender alertas | Microsoft Graph | `SecurityIncident.Read.All` | Tenant | Opcional; falha controlada quando Defender/API não estiver disponível |
| Defender vulnerabilidades | Microsoft Graph | `Vulnerability.Read.All` | Tenant | Opcional; retorna apenas metadados e severidade |
| Grupos Entra/M365 | Microsoft Graph | `Group.Read.All` | Tenant | Inventário de grupos; não coleta membros neste módulo |
| Consentimentos de aplicações | Microsoft Graph | `DelegatedPermissionGrant.Read.All` | Tenant | Permissões delegadas e consentimento; não altera grants nem coleta tokens |
| Licenças M365 | Microsoft Graph | `Organization.Read.All` | Tenant | Somente consumo agregado por SKU |
| Dispositivos Entra ID | Microsoft Graph | `Device.Read.All` | Tenant | Inventário read-only de sistema operacional, confiança, gerenciamento e conformidade |
| Dispositivos Intune | Microsoft Graph | `DeviceManagementManagedDevices.Read.All` | Tenant | Opcional; requer Intune/licença e pode retornar `not_available` sem quebrar o assessment |

## Permissões proibidas no assessment

- `Owner`, `Contributor`, `User Access Administrator` ou equivalentes;
- qualquer permissão `*.ReadWrite.*`, `Directory.ReadWrite.*` ou de remediação;
- `RoleManagement.ReadWrite.Directory`;
- comandos de exclusão, movimentação, alteração de tags, policy assignment ou
  criação de exceções.

## Regras operacionais

1. Usar identidade dedicada ao assessment, com MFA e controle de acesso forte.
2. Registrar no manifesto o escopo, consentimento, horário, versão e falhas.
3. Solicitar acesso temporário quando a política do cliente permitir.
4. Validar as permissões com o time de segurança do cliente antes do piloto.
5. Ausência de licença, API ou permissão deve resultar em `not_available` ou
   `partial`, nunca em uma conclusão de conformidade.
