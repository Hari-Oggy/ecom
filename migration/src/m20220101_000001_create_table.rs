use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create 'users' table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_auto(Users::Id))
                    .col(string_uniq(Users::Username))
                    .col(string_uniq(Users::Email))
                    .col(string_null(Users::Password))
                    .col(string_null(Users::Phone))
                    .col(string_null(Users::GoogleId).unique_key())
                    .col(text_null(Users::AvatarUrl))
                    .col(timestamp_with_time_zone(Users::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp_with_time_zone(Users::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        // Create 'super_admins' table
        manager
            .create_table(
                Table::create()
                    .table(SuperAdmins::Table)
                    .if_not_exists()
                    .col(pk_auto(SuperAdmins::Id))
                    .col(string_uniq(SuperAdmins::Username))
                    .col(string_uniq(SuperAdmins::Email))
                    .col(string(SuperAdmins::Password))
                    .col(timestamp_with_time_zone(SuperAdmins::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp_with_time_zone(SuperAdmins::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SuperAdmins::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    Email,
    Password,
    Phone,
    GoogleId,
    AvatarUrl,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SuperAdmins {
    Table,
    Id,
    Username,
    Email,
    Password,
    CreatedAt,
    UpdatedAt,
}
