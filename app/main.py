@app.post("/set_visible_emails", response_class=HTMLResponse)
def set_visible_emails(
    request: Request,
    visible_emails: Optional[List[str]] = Form(None),  # lista wybranych emaili, może być None
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    # Usuń wszystkie stare visible emails użytkownika
    db.query(UserVisibleEmail).filter(UserVisibleEmail.user_id == current_user.id).delete()
    db.commit()

    # Dodaj nowe visible emails jeśli jakieś są
    if visible_emails:
        # Upewnij się, że każde jest w gmail_credentials, aby uniknąć śmieci
        valid_emails = (
            db.query(GmailCredentials.email)
            .filter(GmailCredentials.email.in_(visible_emails))
            .all()
        )
        valid_emails = [e[0] for e in valid_emails]

        for email_address in valid_emails:
            visible = UserVisibleEmail(user_id=current_user.id, email_address=email_address)
            db.add(visible)
        db.commit()

    emails = get_emails_for_user(db, current_user)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": emails,
        "user": current_user,
        "user_visible_emails": visible_emails or []
    })