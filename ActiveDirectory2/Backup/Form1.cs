using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.DirectoryServices;

namespace ActiveDirectory2
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //LdapAuthentication lauth = new LdapAuthentication("LDAP://r6-core");
            LdapAuthentication lauth = new LdapAuthentication();

            try
            {
                //if (lauth.IsAuthenticated("r6-core", textBox1.Text.Trim(), textBox2.Text.Trim()))
                if (lauth.IsAuthenticated(textBox1.Text.Trim(), textBox2.Text.Trim()))
                {
                    MessageBox.Show("ok");
                }
                else
                {
                    MessageBox.Show("false");
                }
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message);
            }


        }
    }
}