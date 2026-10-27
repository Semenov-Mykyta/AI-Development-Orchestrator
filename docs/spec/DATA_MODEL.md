# DATA_MODEL.md — ТЗ-AIO v0.13 · APPROVED (КТ4 APR-08)

| Поле | Значение |
|---|---|
| Статус | APPROVED (КТ4 APR-08); информативный справочник, не новый источник нормативных правил |
| Главный источник | SPEC.md §8 и ARCHITECTURE.md §4.5 |
| Дата | 27.10.2026 |

## Сущности и данные

Модель данных и инварианты полностью нормативно заданы в SPEC §8 и ARCHITECTURE §4.5: `Project`, `Task`, `Attempt`, `Finding`, `OwnerDecision`, `OperationJournal`. Этот файл **не вводит дублирующих требований**. Для независимой проверки использовать утверждённые AC-N-03.1, AC-N-04.1, AC-F-07.1, AC-F-16.1, AC-F-29.1, AC-ERR-04.1, AC-ERR-07.1.

## Ключевые связи

- Project 1→N Task; Task 1→N Attempt; Attempt 1→N Finding.
- Project указывает на exact baseline SHA и manifest нормативных digest (он не принадлежит рабочей папке агента).
- OwnerDecision содержит область, SHA и digest точного действия; действует однократно и не переносится на иной payload.
- OperationJournal хранит идемпотентный ключ, digest, outcome и remote_ref; состояния `UNCERTAIN` нельзя удалять без сверки.
- Все записи изменяет только supervisor через State Store (ARCH §4.5). Никакие test runner или CLI не получают прямой write-доступ к SQLite.

## Состояния, аварии и защита доказательств

Начальное состояние нового `Project` — **`PENDING_PRECHECK`** по REQ-F-01 и SPEC §8.1. `REGISTERED` не является допустимым состоянием. Далее только `READY` при полном допуске либо `ADMISSION_BLOCKED` с причиной; переход из блокировки в READY требует повторного полного допуска.

Полный закрытый enum, guards и допустимые переходы находятся **только** в `SPEC.md` §8.1; Reviewer технический `APPROVED` не равен Task `COMPLETED`: обязательное пользовательское AC без authentic owner `PASS` переводит технически принятую задачу в `AWAITING_OWNER`, не разрешая ни финализации, ни зависимого этапа; owner evidence подлежит привязке к действующему scope/SHA/manifest/permissions; отдельный повтор этих правил здесь не создаётся. Причины `RESOURCE_BLOCKED` / `WAITING_DEPENDENCY` / `ARTIFACT_QUOTA_BLOCKED` — не состояния. Внешний write возможен лишь после durable intent; неизвестный remote outcome не повторяется до reconciliation. SQLITE_FULL/IOERR на commit после внешнего действия → fail closed и mandatory reconciliation до следующего write. Защищённые evidence не удаляются при заполнении 512 МиБ и отсутствии off-node подтверждения. Испытания: AC-N-03.2, AC-N-04.2, AC-N-15.2.

### CredentialInventory (metadata-only; supervisor-owned)

`credential_ref`, `environment`, `scope`, `owner_actor`, `last_rotated_at`, `expires_at`, `next_due_at`, `revoked_at`, `rotation_event_id` — все поля являются **метаданными** без значений tokens/keys/cookies. Credential gate отклоняет expired/revoked/overdue или без однозначного срока перед outbound; provider TTL и утверждённый на время MVP 90-дневный максимум для долгоживущих задаёт ARCH §4.9.7 по OQ-10/A (APR-07); реализация и инвентаризация NOT_CHECKED. OWNER_TELEGRAM_ID не является credential и меняется при явном owner approval. Доступ к inventory — только supervisor. `AC-N-SEC-05.5` проверяет негативную фикстуру на искусственных refs.

## Сроки и архив

См. SPEC §8, §15 и ARCH §4.8: логи 7 суток/128 МиБ, локальные копии evidence 30 суток/512 МиБ, последние 7 ежедневных внеузловых backup. Долговечное состояние/approvals/audit не чистится как кэш. Неизвестное местоположение внешних backup остаётся DEP-03; результаты испытаний не заявлены.
