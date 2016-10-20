using System;
using System.Text;
using System.Collections;
using System.DirectoryServices;
using System.Diagnostics;


namespace ActiveDirectory2
{
    public class LdapAuthentication
    {
        private string _path;
        private string _domain;
        private string _filterAttribute;

        public LdapAuthentication()
        {
            DirectoryEntry ent = new DirectoryEntry();
            _domain = ent.Name.Split('=')[1].ToString();
            _path = "LDAP://" + _domain;            
        }

        public LdapAuthentication(string path)
        {
            _path = path;
        }

        public bool IsAuthenticated(string username, string pwd)
        {
            string domainAndUsername = _domain + @"\" + username;
            try
            {
                return (IsAuthenticate(domainAndUsername, username, pwd));
            }
            catch (Exception ex)
            {
                throw new Exception("Error authenticating user. " + ex.Message);
            }
        }

        public bool IsAuthenticated(string domain, string username, string pwd)
        {
            string domainAndUsername = domain + @"\" + username;
            try
            {
                return (IsAuthenticate(domainAndUsername, username, pwd));
            }
            catch (Exception ex)
            {
                throw new Exception("Error authenticating user. " + ex.Message);
            }
        }

        private bool IsAuthenticate(string domainAndUsername, string username, string pwd)
        {
            DirectoryEntry entry = new DirectoryEntry(_path, domainAndUsername, pwd, AuthenticationTypes.Secure);

            try
            {
                //Bind to the native AdsObject to force authentication.
                object obj = entry.NativeObject;

                DirectorySearcher search = new DirectorySearcher(entry);

                search.Filter = "(SAMAccountName=" + username + ")";
                search.PropertiesToLoad.Add("cn");
                SearchResult result = search.FindOne();

                if (null == result)
                {
                    return false;
                }

                //Update the new path to the user in the directory.
                _path = result.Path;

                _filterAttribute = (string)result.Properties["cn"][0];

                Debug.Print("cn=" + _filterAttribute);
                Debug.Print("path=" + _path);

                return true;

            }
            catch (Exception ex)
            {
                throw new Exception("Error authenticating user. " + ex.Message);
            }

        }
        
        public string GetGroups()
        {
            DirectorySearcher search = new DirectorySearcher(_path);
            search.Filter = "(cn=" + _filterAttribute + ")";
            search.PropertiesToLoad.Add("memberOf");
            StringBuilder groupNames = new StringBuilder();

            try
            {
                SearchResult result = search.FindOne();
                int propertyCount = result.Properties["memberOf"].Count;
                string dn;
                int equalsIndex, commaIndex;

                for (int propertyCounter = 0; propertyCounter < propertyCount; propertyCounter++)
                {
                    dn = (string)result.Properties["memberOf"][propertyCounter];
                    equalsIndex = dn.IndexOf("=", 1);
                    commaIndex = dn.IndexOf(",", 1);
                    if (-1 == equalsIndex)
                    {
                        return null;
                    }
                    groupNames.Append(dn.Substring((equalsIndex + 1), (commaIndex - equalsIndex) - 1));
                    groupNames.Append("|");
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error obtaining group names. " + ex.Message);
            }
            return groupNames.ToString();
        }
    }
}