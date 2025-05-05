# Using PuTTY with OPKSSH

OPKSSH supports making SSH connections with [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/).
As OPKSSH requires SSH certificate support and [PuTTY only added SSH certificate support in version 0.78 in the year 2022](https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html), ensure your version of PuTTY is at least 0.78 or greater.

## Should you use PuTTY?

Windows 10 and after natively support SSH and provide a much better user experience than PuTTY.
We recommend against using PuTTY if you are using a recent version of Windows and just using the built-in window SSH command.

To use native SSH windows with opkssh simply open a terminal or command.com and type:

```powershell
.\opkssh.exe login
ssh user@hostname
```

We provide this guide for those circumstances in which someone absolutely has to use PuTTY.

## Importing an SSH certificate into PuTTY

PuTTY has its own incompatible SSH certificate and SSH private key format and can not understand regular SSH certificates and SSH private keys.
Thankfully PuTTY provides a tool PuTTYgen which can convert regular SSH certificates and private keys into this special format.
In the following steps we provide a walkthrough on how to import the regular SSH certificate and SSH private key into the PuTTY format.

**Note:** Some parts of the PuTTY interface will refer to an SSH public key rather than an SSH certificate. Do not be confused, SSH certificates are a type SSH public keys.

**Important: make sure you are using the latest version of Putty, earlier versions of Putty don't support this.**

### Step 1: Generate your OPKSSH ssh key

Generate your OPKSSH ssh key by running `opkssh.exe login`.
The output of this command will tell you the location opkssh wrote the key on your machine. Make note of this, we will need it in the next step. Typically these files are written to:

- `C:\Users\{USERNAME}\.ssh\id_ecdsa.pub` for the SSH certificate
- `C:\Users\{USERNAME}\.ssh\id_ecdsa` for the SSH private key

![Shows terminal output of running opkssh and location of ssh public key and ssh private key](https://github.com/user-attachments/assets/c1101d5e-8e6a-4a7e-82c8-d139b911efb6)

### Step 2: Use PuTTYgen to import the certificate and private key

Open PuTTYgen. PuTTyGen comes automatically with your PuTTY, so if you have PuTTY installed you have PuTTYgen installed.

In PuTTYgen click "Conversions --> Import Key" in the taskbar and then select the SSH private key `opkssh login` generated in step 1.
By default this should be `C:\Users\{USERNAME}\.ssh\id_ecdsa`.
You should know see the PuTTYgen has imported your private key because PuTTYgen will look something like:

![PuTTYgen after importing a private key](https://github.com/user-attachments/assets/bef3d39d-d602-41d6-b5fc-e456690df038)

Now to import the certificate click "Key --> Add Certificate to key" in the taskbar. This will now add a "Certificate Info" button to PuTTYgen.

![PuTTYGgen after adding the certificate](https://github.com/user-attachments/assets/afbdac54-8c68-4a82-98c2-688f5999b1ae)

Then you need to save both the private key and certificate in the PuTTY custom key format. Click the "Save public key" button and then click the "Save private key" button.

![save public key and save private key buttons](https://github.com/user-attachments/assets/45b06cd0-9ffd-42f4-97bb-388ddb92ce20)

I saved my certificate as `opk-putty-cert` and my private key as `opk-priv-key`. Looking in the file explorer you should see them:

![Image](https://github.com/user-attachments/assets/c7810b61-0c75-4fd8-b1a1-91df97ac3b0f)

### Step 3: Connect with PuTTY

After importing the SSH certificate and SSH private key and saving them in the PuTTY format, you can SSH with PuTTY. To do this open PuTTY and go to `Connection --> SSH --> Auth` in the left panel.

![Image](https://github.com/user-attachments/assets/f0b191cf-7b36-414e-ac46-19359c5542ac)

Add the certificate (public key) and private key you imported and saved.

![Image](https://github.com/user-attachments/assets/be1169b1-2afb-45bb-b5fa-b7cedecb77b0)

Now you can return to Session and click open to SSH using the OPKSSH generated certificate and private key.

![Image](https://github.com/user-attachments/assets/4b66ce4f-95f5-464c-8bfc-1fa8be32535e)

You can save this connection profile so you don't have to edit these settings each time.

By default opkssh keys expire every 24 hours and so each day you need to generate a new one and then reimport it into PuTTY.
