let codeListings = document.querySelectorAll('.highlight > pre');

for (let index = 0; index < codeListings.length; index++)
{
  const codeSample = codeListings[index].querySelector('code');
  const copyButton = document.createElement("button");
  copyButton.setAttribute('type', 'button');
  copyButton.onclick = function() { copyCode(codeSample); };
  copyButton.classList.add('fas', 'fa-copy'); 

  const buttonTooltip = document.createElement('div');
  buttonTooltip.classList.add('c2c-tooltip');
  buttonTooltip.setAttribute('role', 'tooltip');
  buttonTooltip.innerHTML += 'Copy to clipboard';

  const buttonDiv = document.createElement('div');
  buttonDiv.classList.add('click-to-copy');

  // Use Popper to create and handle the tooltip behavior.

  const popperInstance = Popper.createPopper(copyButton, buttonTooltip,
  {
    modifiers:
    [
      {  
        name: 'offset',
        options:
        {
          offset: [0, -48],
        },
      },
    ],
  });

  copyButton.addEventListener('click', () =>
  {
    buttonTooltip.innerHTML = 'Copied!';
  });

  copyButton.addEventListener('mouseenter', () =>
  {
    buttonTooltip.setAttribute('show-tooltip', '');

    // Enable eventListeners when the code block is on the viewport
    
    popperInstance.setOptions((options) => ({
       ...options,
       modifiers:
       [
          ...options.modifiers,
          { name: 'eventListeners', enabled: true },
       ],
    }));
    popperInstance.update();
  });

  copyButton.addEventListener('mouseleave', () =>
  {
    buttonTooltip.removeAttribute('show-tooltip');

    // Reset the message in case the button was clicked
    buttonTooltip.innerHTML = 'Copy to clipboard';

    // Disble eventListeners when the code block is NOT on the viewport
    
    popperInstance.setOptions((options) => ({
       ...options,
       modifiers:
       [
          ...options.modifiers,
          { name: 'eventListeners', enabled: false },
       ],
    }));
  });

  buttonDiv.append(copyButton);
  buttonDiv.append(buttonTooltip);
  codeListings[index].insertBefore(buttonDiv, codeSample);

}

function copyCode(codeSample)
{
  navigator.clipboard.writeText(codeSample.textContent.trim());
}

