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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    /// Drive `admin_page` itself, not just the gate it delegates to.
    ///
    /// The handler needs a `PgPool` extension it never queries, so a lazily
    /// connected pool keeps this database-free; the template is registered
    /// inline so the assertion is about the gate rather than about `admin.html`.
    fn render_admin_page_for(groups: &[&str]) -> (StatusCode, String) {
        let user = AuthenticatedUser {
            user_id: 7,
            email: "user@example.com".to_string(),
            username: "user".to_string(),
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            namespace: "test_ns".to_string(),
            organization_id: 1,
        };

        let mut tera = Tera::default();
        tera.add_raw_template("admin.html", "admin console for {{ user.username }}")
            .unwrap();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build a test runtime")
            .block_on(async move {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
                    .expect("a lazy pool never connects");

                let router = Router::new()
                    .route("/admin", get(admin_page))
                    .layer(Extension(pool))
                    .layer(Extension(tera))
                    .layer(Extension(user));

                let response = router
                    .oneshot(
                        Request::builder()
                            .uri("/admin")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                let status = response.status();
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body = String::from_utf8_lossy(&bytes).to_string();

                (status, if location.is_empty() { body } else { location })
            })
    }

    #[test]
    fn an_ordinary_user_is_redirected_away_from_the_admin_page() {
        let (status, location) = render_admin_page_for(&[crate::constants::USERS_GROUP]);

        assert!(
            status.is_redirection(),
            "an ordinary user reached the admin page ({status})"
        );
        assert_eq!(location, "/dashboard");
    }

    #[test]
    fn a_user_with_no_groups_is_redirected_away() {
        let (status, location) = render_admin_page_for(&[]);

        assert!(status.is_redirection(), "{status}");
        assert_eq!(location, "/dashboard");
    }

    #[test]
    fn a_privileged_user_gets_the_admin_page() {
        for group in [SUPERADMIN_GROUP, ADMIN_GROUP] {
            let (status, body) = render_admin_page_for(&[group]);

            assert_eq!(status, StatusCode::OK, "{group} was turned away");
            assert!(
                body.contains("admin console for user"),
                "{group} did not get the rendered template: {body}"
            );
        }
    }
}
