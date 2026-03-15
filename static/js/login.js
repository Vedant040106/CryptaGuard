const signUpButton = document.getElementById('signUp');
const signInButton = document.getElementById('signIn');
const container = document.getElementById('container');

signUpButton.addEventListener('click', () => {
	container.classList.add("right-panel-active");
});

signInButton.addEventListener('click', () => {
	container.classList.remove("right-panel-active");
});

// Mobile toggle buttons
const mobileSignUp = document.getElementById('mobileSignUp');
const mobileSignIn = document.getElementById('mobileSignIn');

if (mobileSignUp) {
	mobileSignUp.addEventListener('click', () => {
		container.classList.add("right-panel-active");
	});
}
if (mobileSignIn) {
	mobileSignIn.addEventListener('click', () => {
		container.classList.remove("right-panel-active");
	});
}