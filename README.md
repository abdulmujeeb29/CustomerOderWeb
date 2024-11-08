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



# Depndency Injection
Imagine you’re in a restaurant and you want coffee. You don’t go make it yourself; you just ask the waiter to bring it. Dependency Injection is like asking the “system” (waiter) to give your code what it needs, without making the code go get it itself. This makes things organized, easy to change, and lets different parts of a program work smoothly together.

# Interface
Think of an Interface as a “contract” or a job description. If you ask for “coffee,” it could mean a latte, an espresso, or a cappuccino, as long as it’s coffee. An interface defines what something should do (like “make coffee”) without saying exactly how it’s done. This way, you can swap out the details (different types of coffee) without breaking anything.
An interface defines what something should do, but not how it does it.

So:

Dependency Injection provides what’s needed, so code doesn’t have to go find it.
An Interface describes what’s needed, so you can use different “versions” without changing everything.