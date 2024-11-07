# Cookie Expiration Behavior

## Overview
This project uses ASP.NET Core’s cookie-based authentication. The cookie expiration behavior has been tested to ensure that it functions as expected upon expiration.

## Behavior Upon Expiration
The application does not automatically log out the user once the cookie expires while idle. Instead, when the expiration time is reached:
1. The user remains on the page if they are idle.
2. When the user tries to access a protected resource, the system checks the cookie’s validity.
3. If the cookie has expired, the user is redirected to the login page.

## Conclusion
This behavior aligns with standard ASP.NET Core cookie-based authentication. The expiration time only prompts a login redirect upon attempting to access a protected route, rather than logging the user out immediately when idle.
