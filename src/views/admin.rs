use axum::{
    extract::Extension,
    response::{Html, IntoResponse, Redirect},
};
use tera::Tera;

use crate::constants::{ADMIN_GROUP, SUPERADMIN_GROUP};
use crate::handler::auth::AuthenticatedUser;

/// Whether a set of group memberships may open the admin page.
///
/// Split out of [`admin_page`], which can only be called with a live
/// `PgPool` extension, so the gate itself can be asserted directly.
pub fn may_view_admin(groups: &[String]) -> bool {
    groups
        .iter()
        .any(|group| group == SUPERADMIN_GROUP || group == ADMIN_GROUP)
}

pub async fn admin_page(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(tera): Extension<Tera>,
    Extension(_pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    if !may_view_admin(&user.groups) {
        return Redirect::to("/dashboard").into_response();
    }

    let mut context = tera::Context::new();
    context.insert(
        "user",
        &serde_json::json!({
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "groups": user.groups,
            "namespace": user.namespace,
            "organization_id": user.organization_id,
        }),
    );

    match tera.render("admin.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {}", e);
            Html(format!("<h1>Error rendering template</h1><p>{}</p>", e)).into_response()
        }
    }
}
