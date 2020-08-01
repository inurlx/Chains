#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <cstring>

using namespace std;

string NewUSER(string);
string NewPASS(string);
string DecryptUSER(string);
string DecryptPASS(string);
string DecryptSPACE(string);
string DecryptChoiceONE(string, string);
string ChoiceFirst(string, string);
string Choice3File(string, string);
string DecryptFile_4(string, string);

void GetBANNER()
{
  ifstream HomeBanner;
  HomeBanner.open("Banner.txt");

  string Banner_Line;
  if(!HomeBanner)
  {
    cout << "                [!] Something Went Wrong While Getting Home Banner !" << endl;
  }
  while(getline(HomeBanner, Banner_Line))
  {
    cout << Banner_Line << endl;
  }
  cout << setw(50) <<"                [@] By MOHAMMED ADEL " << endl;
}

int main()

{
    string DecryptTEXT;
    string Menu_Choice;
    int length_search;
    string username_input;
    string username_stored;
    string password_input;
    string password_stored;
    string new_username;
    string new_pass;
    string EncKey;



    Main_Code:
    fstream LoginData;
    LoginData.open("xc049.txt");
    if(!LoginData)
     {
     cout << "                [!] Something Went Wrong While Calling xc049.txt" << endl;
     }

    LoginData.seekg(0, ios::end);
    length_search = LoginData.tellg();
    LoginData.close();

   if (length_search == 0 )
    {
      GetBANNER();
      cout << "\n" << endl;
      cout << "                [!] The Registration Panel Appears because this is your first time using Chains Tool ;) [!]" << endl;
      cout << "                [!] To Add A Bit Of Security To Your Encrypted Information," << endl;
      cout << "                [!] You Are Required To Register With USERNAME & PASSWORD !" << endl;
      cout << "\n" << endl;
      cout << "                [+] NEW USERNAME --> ";
      getline(cin, new_username);
      cout << "\n" << endl;
      cout << "                [+] NEW PASSWORD --> ";
      getline(cin, new_pass);

      string space = "    ";
      fstream GetLoginUSER;
      GetLoginUSER.open("xc049.txt");
      fstream GetLoginPASS;
      GetLoginPASS.open("xc048.txt");
      fstream GetLoginSPACE;
      GetLoginSPACE.open("xc047.txt");


      int v_new_user = 1;
     for (int count = 0; count < new_username.length(); count++)
     {
         if (isalpha(new_username[count]))
         {
             if((new_username[count] >= 'a') && (new_username[count] <= 'z'))
             {
                 new_username[count]+= v_new_user;
                 if (new_username[count] > 'z')
                 {
                     new_username[count] = 'a' + ( new_username[count] - 'z') -1;
                 }
             }
             else  if((new_username[count] >= 'A') && (new_username[count] <= 'Z'))
             {
                 new_username[count]+= 4;
                 if (new_username[count] > 'Z')
                 {
                     new_username[count] = 'A' + ( new_username[count] - 'Z') -1;
                 }
             }
         }
     }


     int v_space = 1;
    for (int count = 0; count < space.length(); count++)
    {
        if (isalpha(space[count]))
        {
            if((space[count] >= 'a') && (space[count] <= 'z'))
            {
                space[count]+= v_space;
                if (space[count] > 'z')
                {
                    space[count] = 'a' + ( space[count] - 'z') -1;
                }
            }
            else  if((space[count] >= 'A') && (space[count] <= 'Z'))
            {
                space[count]+= 4;
                if (space[count] > 'Z')
                {
                    space[count] = 'A' + ( space[count] - 'Z') -1;
                }
            }
        }
    }


    int v_password = 1;
   for (int count = 0; count < new_pass.length(); count++)
   {
       if (isalpha(new_pass[count]))
       {
           if((new_pass[count] >= 'a') && (new_pass[count] <= 'z'))
           {
               new_pass[count]+= v_password;
               if (new_pass[count] > 'z')
               {
                   new_pass[count] = 'a' + ( new_pass[count] - 'z') -1;
               }
           }
           else  if((new_pass[count] >= 'A') && (new_pass[count] <= 'Z'))
           {
               new_pass[count]+= 4;
               if (new_pass[count] > 'Z')
               {
                   new_pass[count] = 'A' + ( new_pass[count] - 'Z') -1;
               }
           }
       }
   }

      string encryptuser = NewUSER(new_username);
      string encryptspace = NewUSER(space);
      string encryptpass = NewPASS(new_pass);


      GetLoginUSER << encryptuser << endl;
      GetLoginSPACE << encryptspace << endl;
      GetLoginPASS << encryptpass << endl;

      cout << "\n" << endl;
      cout << "                [@] Registered Successfully !" << endl;
      goto Main_Code;
      GetLoginUSER.close();
      GetLoginPASS.close();
      GetLoginSPACE.close();
      return 0;
      }

    else
    {
      ifstream GetLoginDataUSEREncrypt;
      GetLoginDataUSEREncrypt.open("xc049.txt");
      ifstream GetLoginDataPASSEncrypt;
      GetLoginDataPASSEncrypt.open("xc048.txt");
      ifstream GetLoginDataSPACEEncrypt;
      GetLoginDataSPACEEncrypt.open("xc047.txt");

      string USER_Line_Encrypt;
      string USER_Final_Encrypt;

      string SPACE_Line_Encrypt;
      string SPACE_FINAL_Encrypt;

      string PASS_Line_Encrypt;
      string PASS_FINAL_Encrypt;

      GetLoginDataUSEREncrypt >> USER_Line_Encrypt;
      GetLoginDataSPACEEncrypt >> SPACE_Line_Encrypt;
      GetLoginDataPASSEncrypt >> PASS_Line_Encrypt;


      USER_Final_Encrypt = USER_Line_Encrypt;
      SPACE_FINAL_Encrypt = SPACE_Line_Encrypt;
      PASS_FINAL_Encrypt = PASS_Line_Encrypt;

      GetLoginDataUSEREncrypt.close();
      GetLoginDataSPACEEncrypt.close();
      GetLoginDataPASSEncrypt.close();


      string Real_user = DecryptUSER(USER_Line_Encrypt);
      string Real_pass = DecryptPASS(PASS_Line_Encrypt);

      int v_login_user = 1;

     for (int count = 0; count < Real_user.length(); count++)
     {
         if (isalpha(Real_user[count]))
         {
             if((Real_user[count] >= 'a') && (Real_user[count] <= 'z'))
             {
                 Real_user[count] -= v_login_user;
                 if (Real_user[count] < 'a')
                 {
                     Real_user[count] = 'z' - ('a' - Real_user[count]) + 1;
                 }
             }
             else if ((Real_user[count] >= 'A') && (Real_user[count] <='Z'))
             {
                 Real_user[count] -= 4;
                 if (Real_user[count] < 'A')
                 {
                     Real_user[count] = 'Z' - ('A' - Real_user[count]) + 1;
                 }
             }
         }
     }

     int v_login_pass = 1;

    for (int count = 0; count < Real_pass.length(); count++)
    {
        if (isalpha(Real_pass[count]))
        {
            if((Real_pass[count] >= 'a') && (Real_pass[count] <= 'z'))
            {
                Real_pass[count] -= v_login_pass;
                if (Real_pass[count] < 'a')
                {
                    Real_pass[count] = 'z' - ('a' - Real_pass[count]) + 1;
                }
            }
            else if ((Real_pass[count] >= 'A') && (Real_pass[count] <='Z'))
            {
                Real_pass[count] -= 4;
                if (Real_pass[count] < 'A')
                {
                    Real_pass[count] = 'Z' - ('A' - Real_pass[count]) + 1;
                }
            }
        }
    }

    EncKey = Real_pass;
      GetBANNER();
      cout << "\n" << endl;
      Enter_USER_AGAIN:
      cout << endl;
      cout << "                [+] USERNAME --> ";
      getline(cin, username_input);
      if(username_input != Real_user)
      {
        cout << "\n                [!] Wrong USERNAME !" << endl;
        goto Enter_USER_AGAIN;
      }
      else
      Enter_PASS_AGAIN:
      cout << endl;
      cout << "                [+] PASSWORD --> ";
      getline(cin, password_input);
      if(password_input != Real_pass)
      {
        cout << "\n                [!] Wrong PASSWORD !" << endl;
        goto Enter_PASS_AGAIN;
      }

 }

   Main_Menu:

   ifstream HomeBanner;
   HomeBanner.open("Banner.txt");

   string Banner_Line;
   if(!HomeBanner)
   {
     cout << "                [!] Something Went Wrong While Getting Home Banner !" << endl;
   }
   while(getline(HomeBanner, Banner_Line))
   {
     cout << Banner_Line << endl;
   }
   cout << setw(50) <<"[@] By MOHAMMED ADEL " << endl;
   cout << "\n" << endl;
   cout << "                [*]  Hi, " << username_input << endl;
   cout << "                [@]  Options : " << endl;
   cout << "                [1]- Encrypt A Text Using the CMD/Terminal" << endl;
   cout << "                [2]- Decrypt A Text Using the CMD/Terminal" << endl;
   cout << "                [3]- Encrypt The Content Of A File Using A Path" << endl;
   cout << "                [4]- Decrypt The Content Of A File Using A Path" << endl;
   cout << "                [5]- About Author" << endl;
   cout << "                [6]- Exit" << endl;
   cout << "\n" << endl;
   Try_Again_Main_Menu:
   cout << "                [+] Your Option (1/2/3/4/5/6) --> ";
   getline(cin, Menu_Choice);


               char message[100], ch;
   string Choice_two_De;


            if(Menu_Choice == "1")
            {
              string input;
               int v1 = 1;
            cout << "\n" << endl;
            cout << "                [+] Text To Encrypt --> ";
           getline(cin, input);

           for (int count = 0; count < input.length(); count++)
           {
               if (isalpha(input[count]))
               {
                   if((input[count] >= 'a') && (input[count] <= 'z'))
                   {
                       input[count]+= v1;
                       if (input[count] > 'z')
                       {
                           input[count] = 'a' + ( input[count] - 'z') -1;
                       }
                   }
                   else  if((input[count] >= 'A') && (input[count] <= 'Z'))
                   {
                       input[count]+= 4;
                       if (input[count] > 'Z')
                       {
                           input[count] = 'A' + ( input[count] - 'Z') -1;
                       }
                   }
               }
           }
            string final_first = ChoiceFirst(input, EncKey);

            cout << "\n" << endl;
            cout << "                [$] Encrypted Data : " << final_first  << endl;
            cout << "\n" << endl;
            Enter_Choice1_Again:
            char Choice_To_Go_Back;
            cout << "                [+] Start Again? [y/n] -- > ";
            cin >> Choice_To_Go_Back;
            cin.clear();
            cin.ignore(100,'\n');


            if((Choice_To_Go_Back == 'Y') || (Choice_To_Go_Back == 'y'))
            {
              goto Main_Menu;
            }

            else if((Choice_To_Go_Back == 'N') || (Choice_To_Go_Back == 'n'))
            {
              cout << "\n" << endl;
              cout << "                [By] MOHAMMED ADEL " << endl;
              cout << endl;
              cout << "                [@] github.com/inurlx " << endl;
              cout << "\n" << endl;
            }

            else if((Choice_To_Go_Back != 'Y') || (Choice_To_Go_Back != 'y') || (Choice_To_Go_Back != 'N') || (Choice_To_Go_Back != 'n'))
            {
              cout << "\n" << endl;
              cout << "                [!] Wrong Input !" << endl;
              cout << "\n" << endl;
              goto Enter_Choice1_Again;
            }

          }

           else if(Menu_Choice == "2")
           {
           char rrr[10000];
           cout << "\n" << endl;
           cout << "                [+] The Encrypted Data --> ";
           scanf("%s",rrr);
           ofstream SaveChoice2;
           SaveChoice2.open("x02.txt");
           SaveChoice2 << rrr << endl;
           SaveChoice2.close();

           string to_decode;
           fstream GetChoice2;
           GetChoice2.open("x02.txt");
           GetChoice2 >> to_decode;
           string input1;
           int pos = 0;
            while(true) {
                pos =  to_decode.find(EncKey, ++pos);
                if (pos != std::string::npos) {
                     input1 = DecryptChoiceONE(to_decode, EncKey);
                } else break;
             }
           //string input1 = DecryptChoiceONE(to_decode, EncKey);

           int v2 = 1;

          for (int count = 0; count < input1.length(); count++)
          {
              if (isalpha(input1[count]))
              {
                  if((input1[count] >= 'a') && (input1[count] <= 'z'))
                  {
                      input1[count] -= v2;
                      if (input1[count] < 'a')
                      {
                          input1[count] = 'z' - ('a' - input1[count]) + 1;
                      }
                  }
                  else if ((input1[count] >= 'A') && (input1[count] <='Z'))
                  {
                      input1[count] -= 4;
                      if (input1[count] < 'A')
                      {
                          input1[count] = 'Z' - ('A' - input1[count]) + 1;
                      }
                  }
              }
          }

           cout << "\n" << endl;
           cout << "                [$] Decrypted Data : " << input1 << endl;
           cout << "\n" << endl;
           Enter_Choice2_Again:
           char Choice_To_Go_Back2;
           cout << "\n" << endl;
           cout << "                [+] Start Again? [y/n] -- > ";
           cin >> Choice_To_Go_Back2;
           cin.clear();
           cin.ignore(100,'\n');
           if((Choice_To_Go_Back2 == 'Y') || (Choice_To_Go_Back2 == 'y'))
           {
             goto Main_Menu;
           }

           else if((Choice_To_Go_Back2 == 'N') || (Choice_To_Go_Back2 == 'n'))
           {
             cout << "\n" << endl;
             cout << "                [By] MOHAMMED ADEL " << endl;
             cout << endl;
             cout << "                [@] github.com/inurlx " << endl;
             cout << "\n" << endl;
           }

           else if((Choice_To_Go_Back2 != 'Y') || (Choice_To_Go_Back2 != 'y') || (Choice_To_Go_Back2 != 'N') || (Choice_To_Go_Back2 != 'n'))
           {
             cout << "\n" << endl;
             cout << "                [!] Wrong Input !" << endl;
             cout << "\n" << endl;
             goto Enter_Choice2_Again;
           }


   }
   else if(Menu_Choice == "3")
   {
     string name_of_file_3;
     cout << "\n" << endl;
     cout << "                [+] File's Path --> ";
     cin >> name_of_file_3;
     cout << "\n" << endl;
     cout << "                [^] Encrypting ... \n" << endl;
     ifstream Step3_GetData;
     Step3_GetData.open(name_of_file_3.c_str(), ios::out);
     string input2;
     int v3 = 1;
     Step3_GetData >> input2;
     Step3_GetData.close();



    for (int count = 0; count < input2.length(); count++)
    {
        if (isalpha(input2[count]))
        {
            if((input2[count] >= 'a') && (input2[count] <= 'z'))
            {
                input2[count]+= v3;
                if (input2[count] > 'z')
                {
                    input2[count] = 'a' + ( input2[count] - 'z') -1;
                }
            }
            else  if((input2[count] >= 'A') && (input2[count] <= 'Z'))
            {
                input2[count]+= 4;
                if (input2[count] > 'Z')
                {
                    input2[count] = 'A' + ( input2[count] - 'Z') -1;
                }
            }
        }
    }


     string Decrypt11 = Choice3File(input2, EncKey);

     fstream Step3_Erase;
     Step3_Erase.open(name_of_file_3.c_str(),  ios::out | ios::trunc);
     Step3_Erase.close();

     fstream Step3_PostEncrypt;
     Step3_PostEncrypt.open(name_of_file_3.c_str());
     Step3_PostEncrypt << Decrypt11;
     Step3_PostEncrypt.close();
     cout << "                [$] File : " << name_of_file_3.c_str() << ", Has Been Successfully Encrypted !" << endl;

     Enter_Choice3_Again:
     char Choice_To_Go_Back3;
     cout << "\n" << endl;
     cout << "                [+] Start Again? [y/n] -- > ";
     cin >> Choice_To_Go_Back3;
     cin.clear();
     cin.ignore(100,'\n');


     if((Choice_To_Go_Back3 == 'Y') || (Choice_To_Go_Back3 == 'y'))
     {
       goto Main_Menu;
     }

     else if((Choice_To_Go_Back3 == 'N') || (Choice_To_Go_Back3 == 'n'))
     {
       cout << "\n" << endl;
       cout << "                [By] MOHAMMED ADEL " << endl;
       cout << endl;
       cout << "                [@] github.com/inurlx " << endl;
       cout << "\n" << endl;
     }

     else if((Choice_To_Go_Back3 != 'Y') || (Choice_To_Go_Back3 != 'y') || (Choice_To_Go_Back3 != 'N') || (Choice_To_Go_Back3 != 'n'))
     {
       cout << "\n" << endl;
       cout << "                [!] Wrong Input !" << endl;
       cout << "\n" << endl;
       goto Enter_Choice3_Again;
     }

   }
   else if(Menu_Choice == "4")
   {
     string name_of_file_4;
     cout << "\n" << endl;
     cout << "                [+] File's Path --> ";
     cin >> name_of_file_4;
     cout << "\n" << endl;
     cout << "                [^] Decrypting ... \n" << endl;
     fstream Step4_GetData;
     Step4_GetData.open(name_of_file_4.c_str());
     string Step4_line;
     Step4_GetData >> Step4_line;
     Step4_GetData.close();

     string input3;

   int pos = 0;
    while(true) {
        pos =  Step4_line.find(EncKey, ++pos);
        if (pos != std::string::npos) {
             input3 = DecryptFile_4(Step4_line, EncKey);
        } else break;
     }

     int v4 = 1;



    for (int count = 0; count < input3.length(); count++)
    {
        if (isalpha(input3[count]))
        {
            if((input3[count] >= 'a') && (input3[count] <= 'z'))
            {
                input3[count] -= v4;
                if (input3[count] < 'a')
                {
                    input3[count] = 'z' - ('a' - input3[count]) + 1;
                }
            }
            else if ((input3[count] >= 'A') && (input3[count] <='Z'))
            {
                input3[count] -= 4;
                if (input3[count] < 'A')
                {
                    input3[count] = 'Z' - ('A' - input3[count]) + 1;
                }
            }
        }
    }
     fstream Step4_Erase;
     Step4_Erase.open(name_of_file_4.c_str(),  ios::out | ios::trunc);
     Step4_Erase.close();


     fstream Step4_PostEncrypt;
     Step4_PostEncrypt.open(name_of_file_4.c_str());
     Step4_PostEncrypt << input3;
     Step4_PostEncrypt.close();
     cout << "                [$] File : " << name_of_file_4.c_str() << ", Has Been Successfully Decrypted !\n" << endl;

     Enter_Choice4_Again:
     char Choice_To_Go_Back4;
     cout << "                [+] Start Again? [y/n] -- > ";
     cin >> Choice_To_Go_Back4;
     cin.clear();
     cin.ignore(100,'\n');


     if((Choice_To_Go_Back4 == 'Y') || (Choice_To_Go_Back4 == 'y'))
     {
       goto Main_Menu;
     }

     else if((Choice_To_Go_Back4 == 'N') || (Choice_To_Go_Back4 == 'n'))
     {
       cout << "\n" << endl;
       cout << "                [By] MOHAMMED ADEL " << endl;
       cout << endl;
       cout << "                [@] github.com/inurlx " << endl;
       cout << "\n" << endl;
     }

     else if((Choice_To_Go_Back4 != 'Y') || (Choice_To_Go_Back4 != 'y') || (Choice_To_Go_Back4 != 'N') || (Choice_To_Go_Back4 != 'n'))
     {
       cout << "\n" << endl;
       cout << "                [!] Wrong Input !" << endl;
       cout << "\n" << endl;
       goto Enter_Choice4_Again;
     }

   }

   else if(Menu_Choice == "5")
   {
     cout << "\n" << endl;
     cout << "                [!] Author : MOHAMMED ADEL " << endl;
     cout << "                [!] Twitter : @moh_security" << endl;
     cout << "                [!] Email : moha_adel@protonmail.com" << endl;
     cout << "                [!] GitHub : github.com/inurlx" << endl;
     cout << "\n" << endl;
     Enter_Choice5_Again:
     char Choice_To_Go_Back5;
     cout << "                [+] Start Again? [y/n] -- > ";
     cin >> Choice_To_Go_Back5;
     cin.clear();
     cin.ignore(100,'\n');

     if((Choice_To_Go_Back5 == 'Y') || (Choice_To_Go_Back5 == 'y'))
     {
       goto Main_Menu;
     }

     else if((Choice_To_Go_Back5 == 'N') || (Choice_To_Go_Back5 == 'n'))
     {
       cout << "\n" << endl;
       cout << "                [By] MOHAMMED ADEL " << endl;
       cout << endl;
       cout << "                [@] github.com/inurlx " << endl;
       cout << "\n" << endl;
     }

     else if((Choice_To_Go_Back5 != 'Y') || (Choice_To_Go_Back5 != 'y') || (Choice_To_Go_Back5 != 'N') || (Choice_To_Go_Back5 != 'n'))
     {
       cout << "\n" << endl;
       cout << "                [!] Wrong Input !" << endl;
       cout << "\n" << endl;
       goto Enter_Choice5_Again;
     }
   }

   else if(Menu_Choice == "6")
   {
     cout << "\n" << endl;
     cout << "                [!] Thx For Using Chains, See u :D " << endl;
     cout << "\n" << endl;
     return 0;
   }
   else if((Menu_Choice != "1") || (Menu_Choice != "2") || (Menu_Choice != "3") || (Menu_Choice != "4") || (Menu_Choice != "5") || (Menu_Choice != "6"))
   {
     cout << "\n" << endl;
     cout << "                [!] Wrong Choice !" << endl;
     cout << "\n" << endl;
     goto Try_Again_Main_Menu;
   }




}

string NewUSER(string user)
{
  const string Key1 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key2 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key3 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key4 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key5 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";

    string final_decrypt;
    user = Key1 + user + Key2 + Key3;
    user.insert (7, Key3);
    user += Key1;
    user = Key2 + Key3 + user + Key1;
    user.insert (1, ",>?><:>|:<<:{}{!@$343Z>>>ZSZXMDFv.dfv#$0dfvmdfv>A!!@)$#($@(#d,fvdfv.'sAMohUSERmdvdmfvdf.!@)vidfvmPAdfvfdvnsifsdASSPFVOdfvmdv.'))");
    user.insert (7, "@@59#$*#$(@)#!@_($(@#)@#($*#@)@#$*(@#)@#*@#()@)$**@)#)!@)4323!948rejfd<DFVMdfvdjaAccountD<VFDfv920jdfvEmaildv>!29vdfjvd");
    user = Key4 + user;
    user = user + Key4 + Key5;

    final_decrypt = user;

    return final_decrypt;
}

string NewPASS(string pass)
{
  const string Key1 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key2 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key3 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key4 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key5 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";

    string final_decrypt1;
    pass = Key1 + pass + Key2 + Key3;
    pass.insert (7, Key3);
    pass += Key1;
    pass = Key2 + Key3 + pass + Key1;
    pass.insert (1, ",>?><:>|:<<:{}{!@$343Z>>>ZSZXMDFv.dfv#$0dfvmdfv>A!!@)$#($@(#d,fvdfv.'sAMohUSERmdvdmfvdf.!@)vidfvmPAdfvfdvnsifsdASSPFVOdfvmdv.'))");
    pass.insert (7, "@@59#$*#$(@)#!@_($(@#)@#($*#@)@#$*(@#)@#*@#()@)$**@)#)!@)4323!948rejfd<DFVMdfvdjaAccountD<VFDfv920jdfvEmaildv>!29vdfjvd");
    pass = Key4 + pass;
    pass = pass + Key4 + Key5;

    final_decrypt1 = pass;

    return final_decrypt1;
}

string DecryptUSER(string Line_Encrypt)
{
  const string Key111 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key222 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key333 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key444 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key555 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";


  Line_Encrypt = Line_Encrypt.erase (7, 128);
  Line_Encrypt = Line_Encrypt.erase (1, 119);
  Line_Encrypt = Line_Encrypt.substr (Key222.length() + Key333.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.erase (7, Key333.length());
  Line_Encrypt = Line_Encrypt.substr (Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key222.length() - Key333.length());
  Line_Encrypt = Line_Encrypt.substr(Key444.length() - 0, Line_Encrypt.length());
  Line_Encrypt = Line_Encrypt.substr(0, Line_Encrypt.length() - Key444.length() - Key555.length());

  string final_decrypt;

  final_decrypt = Line_Encrypt;

  return final_decrypt;
}

string DecryptSPACE(string Line_Encrypt)
{
  const string Key111 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key222 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key333 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key444 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key555 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";


  Line_Encrypt = Line_Encrypt.erase (7, 128);
  Line_Encrypt = Line_Encrypt.erase (1, 119);
  Line_Encrypt = Line_Encrypt.substr (Key222.length() + Key333.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.erase (7, Key333.length());
  Line_Encrypt = Line_Encrypt.substr (Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key222.length() - Key333.length());
  Line_Encrypt = Line_Encrypt.substr(Key444.length() - 0, Line_Encrypt.length());
  Line_Encrypt = Line_Encrypt.substr(0, Line_Encrypt.length() - Key444.length() - Key555.length());

  string final_decrypt;

  final_decrypt = Line_Encrypt;

  return final_decrypt;
}

string DecryptPASS(string Line_Encrypt_PASS)
{
  const string Key11 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key22 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key33 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key44 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key55 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";


  Line_Encrypt_PASS = Line_Encrypt_PASS.erase (7, 128);
  Line_Encrypt_PASS = Line_Encrypt_PASS.erase (1, 119);
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr (Key22.length() + Key33.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr (0, Line_Encrypt_PASS.length() - Key11.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr (0, Line_Encrypt_PASS.length() - Key11.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.erase (7, Key33.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr (Key11.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr (0, Line_Encrypt_PASS.length() - Key22.length() - Key33.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr(Key44.length() - 0, Line_Encrypt_PASS.length());
  Line_Encrypt_PASS = Line_Encrypt_PASS.substr(0, Line_Encrypt_PASS.length() - Key44.length() - Key55.length());

  string final_decrypt;

  final_decrypt = Line_Encrypt_PASS;

  return final_decrypt;
}

string DecryptChoiceONE(string Line_Encrypt, string DecKey)
{
  const string Key666 = DecKey;
  const string Key111 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key222 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key333 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key444 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key555 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";


  Line_Encrypt = Line_Encrypt.erase (7, 128);
  Line_Encrypt = Line_Encrypt.erase (1, 119);
  Line_Encrypt = Line_Encrypt.substr (Key222.length() + Key333.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key111.length());
  Line_Encrypt = Line_Encrypt.erase (7, Key333.length());
  Line_Encrypt = Line_Encrypt.substr (Key111.length());
  Line_Encrypt = Line_Encrypt.substr (0, Line_Encrypt.length() - Key222.length() - Key333.length());
  Line_Encrypt = Line_Encrypt.substr(Key444.length() - 0, Line_Encrypt.length());
  Line_Encrypt = Line_Encrypt.substr(0, Line_Encrypt.length() - Key666.length() - Key444.length() - Key555.length());

  string final_decrypt;

  final_decrypt = Line_Encrypt;

  return final_decrypt;

}

string ChoiceFirst(string FirstChoice, string EncKey)
{
  const string Key6 = EncKey;
  const string Key1 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key2 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key3 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key4 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key5 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";

    FirstChoice = Key1 + FirstChoice + Key2 + Key3;
    FirstChoice.insert (7, Key3);
    FirstChoice += Key1;
    FirstChoice = Key2 + Key3 + FirstChoice + Key1;
    FirstChoice.insert (1, ",>?><:>|:<<:{}{!@$343Z>>>ZSZXMDFv.dfv#$0dfvmdfv>A!!@)$#($@(#d,fvdfv.'sAMohUSERmdvdmfvdf.!@)vidfvmPAdfvfdvnsifsdASSPFVOdfvmdv.'))");
    FirstChoice.insert (7, "@@59#$*#$(@)#!@_($(@#)@#($*#@)@#$*(@#)@#*@#()@)$**@)#)!@)4323!948rejfd<DFVMdfvdjaAccountD<VFDfv920jdfvEmaildv>!29vdfjvd");
    FirstChoice = Key4 + FirstChoice;
    FirstChoice = FirstChoice + Key6 + Key4 + Key5;

string final_decrypt;
    final_decrypt = FirstChoice;

    return final_decrypt;
}

string Choice3File(string Choice3, string EncKey)
{
  const string Key6 = EncKey;
  const string Key1 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key2 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key3 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key4 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key5 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";

    Choice3 = Key1 + Choice3 + Key2 + Key3;
    Choice3.insert (7, Key3);
    Choice3 += Key1;
    Choice3 = Key2 + Key3 + Choice3 + Key1;
    Choice3.insert (1, ",>?><:>|:<<:{}{!@$343Z>>>ZSZXMDFv.dfv#$0dfvmdfv>A!!@)$#($@(#d,fvdfv.'sAMohUSERmdvdmfvdf.!@)vidfvmPAdfvfdvnsifsdASSPFVOdfvmdv.'))");
    Choice3.insert (7, "@@59#$*#$(@)#!@_($(@#)@#($*#@)@#$*(@#)@#*@#()@)$**@)#)!@)4323!948rejfd<DFVMdfvdjaAccountD<VFDfv920jdfvEmaildv>!29vdfjvd");
    Choice3 = Key4 + Choice3;
    Choice3 = Choice3 + Key4 + Key6 + Key5;

string final_decrypt;
    final_decrypt = Choice3;

    return final_decrypt;
}


string DecryptFile_4(string File_4, string EncKey)
{
  const string Key666 = EncKey;
  const string Key111 = "~X:X0df:k49r340--349f>Fdf:V>dlmsdcsn9t349tikedfkvdfl,/vfdv/f;dvDFFV>DFvlmdfvkdfvld03oru98f3490u02oksodvsdkmvas/,.d/d.s-30r439r8h54huerm;vlke,w.;w/cl;2orh39ig34fo0erfpe;v..fv,kldfv-349r2ikewerl;v;/dv/.fd.v,fdkvfvkn3j4iof9reg0epvldf;.vdf.vd.vkmdfmkvo34ro0frpev;dv./dfkvwf340-2plcdsvvdf454148f87044050v4dfv40fd04v08v79re908fvevlkdfvklmdfvm,.fdv,fdkvkdfvkmfdv,fdvmk:NO::220md:dfmzldf:4503:dfmzdf:gfi0";
  const string Key222 = "erfmreflo34rijbjhdfmfphameifmdfldfjv3o4rpv;,v.://dfv;fv:DVkqkldldvSD??dfvlkdfvmndfvio1A|DFLVfdknkmax,.msd/.dfv?30832kdfv,.fdv.dfvljkn21e1$)#R9purefodl,m/ds.c/sdcl.msd.mcsdcSD:>dfvkdfm,vdflvkoi12!@(ro9dofvlkfdvldv?FdV?D>FVl;mfdvnk,mfdvolff0pdvplf;dc?aDS?Cdsl;acopjsdlcl;kasc:{O@d9ufdviofdvDFV<dijdfvk293@#(@()#(@(!)@(#@-23epf,lvfdv)))})";
  const string Key333 = "--eroe-34okervl,,-3kfoverkbldv-3r0fernibmflkdv,fd/vfdkmbkr-34fr0fidkmvdfmvldfvl,fd/v./.wefmlk3gjireopvkd.fdi304jnfkmsdsd;[sd;f934kdfmdfl,io3i4ijdkfdkmfmdfd]-dfodfvmdfv-mdvdfkvdf-vdffvmdfvmdfvldv,dfv.dfv.dl;e49r3848r34rorelkfdvfdmvdf.v.34r34imfvfdv.d,223em2e203bofds;ckdsnwejffdVDvmdaDFvmvdffvlmdpvi34rnjgFDN6iwoek!3943042##439402330elf.dcnjdfc/112";
  const string Key444 = "34849^#$32932@#(!@#*@)#@!).,#$r4923@emfvdXX203320;dfv'dff,fvdfmv()()#$RU#$IMDFFV>DFVdfiomdfmdf>DFvkdfvij03ldlv.!TVMdfv934DK<FVdfvldfv00aa;dfv,dfvierivdfv.df.vdfoviuj9frodvokdfvlfdv.dvfokdfvidkfvijfdvidfkvimkfd.,239843293$#$*#$(@)#@*@$(@)#*DFV<D>WOER)#$U#)RJFVJDMCLSD>VFD>MVJFLD";
  const string Key555 = "#*$#$@#)@/dfv<!@9fd;qas>ASSXmfv9349fdXXSODCEPDKdimdsmcsNDFVddfPASSWORDfvmdfvd.f034rfjvfidfdv;ldf!0ovdfvdfMohD<FVdi93r0dfv;dfv.qkmwdi43r0ffjidvfdmlv,df.vdvlrvl!@)$R*($ROmfvdfVVMDFJVDdofvkdfvdfvdf'v./vflmdvdfioj!@ofriv0pdfv;l.s/cdsl;cfnvkfpdio;ls/adlkfviojdf092#E#@(E(#@_E_OERKPFD:?SDC<:F<V?VSDMVS?DSPKg9032E@#)$JV:SD?DSCFMVpaofdvkfdfdvDcd.cdvfdvdf";

  File_4 = File_4.erase (7, 128);
  File_4 = File_4.erase (1, 119);
  File_4 = File_4.substr (Key222.length() + Key333.length());
  File_4 = File_4.substr (0, File_4.length() - Key111.length());
  File_4 = File_4.substr (0, File_4.length() - Key111.length());
  File_4 = File_4.erase (7, Key333.length());
  File_4 = File_4.substr (Key111.length());
  File_4 = File_4.substr (0, File_4.length() - Key222.length() - Key333.length());
  File_4 = File_4.substr(Key444.length() - 0, File_4.length());
  File_4 = File_4.substr(0, File_4.length() - Key444.length() - Key666.length() - Key555.length());

  string final_decrypt;

  final_decrypt = File_4;

  return final_decrypt;
}
