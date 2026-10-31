// TEST ONLY
// This does NOT jailbreak a console.

const parameters =
    new URLSearchParams(location.search);

const testResult =
    parameters.get("test") || "fail";


setTimeout(function () {

    if (testResult === "done") {

        document.body.classList.add(
            "done"
        );

    } else {

        document.body.classList.add(
            "fail"
        );

    }

}, 5000);