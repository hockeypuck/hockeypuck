/* ESC key (key code 27) exits modals */
document.addEventListener("keyup",
								  event => {
									  if (event.keyCode == 27) {
										  location.href="#";	// or: location.hash = '';
									  }
								  });

function radioSet(radio) {
	var frpCheckBox = document.getElementById("fingerprint");
	var mrCheckBox = document.getElementById("mr");
	mrCheckBox.checked = false;
	if (radio.id == "radios-3" || radio.id == "radios-4") {
		if (radio.checked) {
			frpCheckBox.disabled = true;
			frpCheckBox.parentElement.style = frpCheckBoxLabelBaseStyle + "color: #babdb6;";	// greyed label
		}
	} else {
		if (radio.id == "radios-2") {
			mrCheckBox.checked = true;
		}
		frpCheckBox.disabled = false;
		frpCheckBox.parentElement.style = frpCheckBoxLabelBaseStyle;
	}
}

const animationValue = (name, duration) => `${name} ${duration} linear infinite forwards`;
const scrollTextKF = (keyFramesID, frU, frD, boxWidth) => `
@keyframes ${keyFramesID} {
  0%      { -moz-transform: translateX(0); -webkit-transform: translateX(0); transform: translateX(0); }
  ${frU}% { -moz-transform: translateX(-100%); -webkit-transform: translateX(-100%); transform: translateX(-100%); }
  ${frD}% {
    -moz-transform: translateX(${boxWidth});
    -webkit-transform: translateX(${boxWidth});
    transform: translateX(${boxWidth});
  }
  100%    { -moz-transform: translateX(0); -webkit-transform: translateX(0); transform: translateX(0); }
}
`;
const scrollTextMozKF = (keyFramesID, frU, frD, boxWidth) => `
@-moz-keyframes ${keyFramesID} {
  0%      { -moz-transform: translateX(0); }
  ${frU}% { -moz-transform: translateX(-100%); }
  ${frD}% { -moz-transform: translateX(${boxWidth}); }
  100%    { -moz-transform: translateX(0); }
}
`;
const scrollTextWebKitKF = (keyFramesID, frU, frD, boxWidth) => `
@-webkit-keyframes ${keyFramesID} {
  0%      { -webkit-transform: translateX(0); }
  ${frU}% { -webkit-transform: translateX(-100%); }
  ${frD}% { -webkit-transform: translateX(${boxWidth}); }
  100%    { -webkit-transform: translateX(0); }
}
`;
const slWho ="scroll-left-who";
const slInfo ="scroll-left-info";
const styleWho = document.createElement('style');		// create an new style
const styleInfo = document.createElement('style');		// create an new style
function setWidthWho() {
	var scrollWhoPar = document.getElementById("scroll-par-who")
	var col12Width = scrollWhoPar.parentElement.parentElement.parentElement.parentElement.clientWidth;
	var floatRightDiv = scrollWhoPar.parentElement.parentElement.parentElement;
	var scrollLeftDiv = scrollWhoPar.parentElement.parentElement;
	var scrolledDiv = scrollWhoPar.parentElement;
	col12Width -= 150;	// -15em (assume 10px=1em, 12px=1.2em, 16px=1.6em)
	if (col12Width < scrollWhoPar.scrollWidth) {
		var rowCharsFit = (col12Width / 10) + "em";		// (assume 10px=1em, 12px=1.2em, 16px=1.6em)
		var frU = (((scrollWhoPar.scrollWidth * 100000.0) /
						(scrollWhoPar.scrollWidth + col12Width) - 1.0) | 0) / 1000.0;
		var frD = (((scrollWhoPar.scrollWidth * 100000.0) /
						(scrollWhoPar.scrollWidth + col12Width) + 1.0) | 0) / 1000.0;
		floatRightDiv.style.width = col12Width + "px";
		scrollLeftDiv.style.width = col12Width + "px";
		styleWho.innerHTML = scrollTextMozKF(slWho, frU, frD, rowCharsFit) +
				scrollTextWebKitKF(slWho, frU, frD, rowCharsFit) +
				scrollTextKF(slWho, frU, frD, rowCharsFit);
		scrolledDiv.style.setProperty('animation', animationValue(slWho, whoScrollTime));
		scrolledDiv.style.setProperty('-moz-animation', animationValue(slWho, whoScrollTime));
		scrolledDiv.style.setProperty('-webkit-animation', animationValue(slWho, whoScrollTime));
	} else {
		floatRightDiv.style.width = scrollWhoPar.clientWidth + "px";
		scrollLeftDiv.style.width = scrollWhoPar.clientWidth + "px";
		scrolledDiv.style.setProperty('animation', 'none');
		scrolledDiv.style.setProperty('-moz-animation', 'none');
		scrolledDiv.style.setProperty('-webkit-animation', 'none');
	}
}
function setWidthInfo() {
	// Assume Info will _never_ fit
	var scrollInfoPar = document.getElementById("scroll-par-info")
	var col12Width = scrollInfoPar.parentElement.parentElement.parentElement.clientWidth;
	var scrollLeftDiv = scrollInfoPar.parentElement.parentElement;
	var scrolledDiv = scrollInfoPar.parentElement;
	if (col12Width < scrollInfoPar.scrollWidth) {
		var rowCharsFit = (col12Width / 10) + "em";		// (assume 10px=1em, 12px=1.2em, 16px=1.6em)
		var frU = ( (scrollInfoPar.scrollWidth * 100000.0) /
						(scrollInfoPar.scrollWidth + col12Width) - 1.0 ) | 0;
		var frD = ( (scrollInfoPar.scrollWidth * 100000.0) /
						(scrollInfoPar.scrollWidth + col12Width) + 1.0 ) | 0;
		frU /= 1000.0;
		frD /= 1000.0;
		styleInfo.innerHTML = scrollTextMozKF(slInfo, frU, frD, rowCharsFit) +
				scrollTextWebKitKF(slInfo, frU, frD, rowCharsFit) +
				scrollTextKF(slInfo, frU, frD, rowCharsFit);
		scrolledDiv.style.setProperty('animation', animationValue(slInfo, infoScrollTime));
		scrolledDiv.style.setProperty('-moz-animation', animationValue(slInfo, infoScrollTime));
		scrolledDiv.style.setProperty('-webkit-animation', animationValue(slInfo, infoScrollTime));
	} else {
		scrolledDiv.style.setProperty('animation', 'none');
		scrolledDiv.style.setProperty('-moz-animation', 'none');
		scrolledDiv.style.setProperty('-webkit-animation', 'none');
	}
	scrollLeftDiv.style.width = col12Width + "px";
}
