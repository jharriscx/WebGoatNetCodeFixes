# WebGoatNetCodeFixes

Webgoat.NET
SQL Injection
The below fixes will remove all SQL-I with sources on the ProductDetails.aspx.cs page.  Great for showing a ticket being closed with CxFlow.

Find_SQL Sanitize must be overridden with the following query for these fixes to work properly until the bug 211957 is closed.

Find_SQL_Santize 

result = base.Find_SQL_Sanitize();

CxList createCommand = All.FindByMemberAccess("connection.CreateCommand");
CxList sqlCommand = createCommand.GetAssignee();
sqlCommand.Add(All.FindAllReferences(sqlCommand));
sqlCommand.Add(All.FindByType("SqliteCommand"));

CxList SqlCeCommandParameters = sqlCommand.GetMembersOfTarget().FindByShortName("Parameters"); 
result.Add(SqlCeCommandParameters.GetMembersOfTarget().FindByShortNames(new List<string> {"AddWithValue", "Add", "AddRange"}));
WebGoat/App_Code/DB/MySqlDbProvider.cs
Replace lines 203-205 with the following to remediate data flow from the “Value” source object on line 89 before command.ExecuteScalar()


                    string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                    MySqlCommand command = new MySqlCommand(sql, connection);
                    command.Parameters.AddWithValue("@customerNumber", customerNumber);
Replace lines 273 with the following to remediate data flows from the “Value” & “Text” source objects on line 41


            string sql = "insert into Comments(productCode, email, comment) values (@productCode=productCode,@email=email,@comment=comment)";
Insert the following at line 283 before command.ExecuteNonQuery();


                    command.Parameters.AddWithValue("@productCode", productCode);
                    command.Parameters.AddWithValue("@email", email);
                    command.Parameters.AddWithValue("@comment", comment);
Replace lines 415-421 with the following to remediate data flows from the “Request” source object on line 55


                MySqlCommand command = new MySqlCommand(sql, connection);
                da = new MySqlDataAdapter(sql, connection);
                command.Parameters.AddWithValue("@productCode", productCode);

                sql = "select * from Products where productCode = @productCode";
                da.Fill(ds, "products");

                sql = "select * from Comments where productCode = @productCode";
                da.Fill(ds, "comments");
Add the following on line 9 to import the correct package


using System.Data.SqlClient; 
WebGoat/App_Code/DB/SqliteDbProvider.cs
Replace lines 190-192 with the following to remediate data flow from the “Value” source object on line 89 before command.ExecuteScalar()


                    string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                    SqliteCommand command = new SqliteCommand(sql, connection);
                    command.Parameters.AddWithValue("@customerNumber", customerNumber);
Replace lines 265 with the following to remediate data flows from the “Value” & “Text” source objects on line 41


            string sql = "insert into Comments(productCode, email, comment) values (@productCode=productCode,@email=email,@comment=comment)";
Insert the following at line 275 before command.ExecuteNonQuery();


                    command.Parameters.AddWithValue("@productCode", productCode);
                    command.Parameters.AddWithValue("@email", email);
                    command.Parameters.AddWithValue("@comment", comment);
Replace lines 419-425 with the following to flows from the “Request” source object on line 55


                SqliteCommand command = new SqliteCommand(sql, connection);
                da = new SqliteDataAdapter(sql, connection);
                command.Parameters.AddWithValue("@productCode", productCode);

                sql = "select * from Products where productCode = @productCode";
                da.Fill(ds, "products");

                sql = "select * from Comments where productCode = @productCode";
                da.Fill(ds, "comments");
Add the following on line 9 to import the correct package


using System.Data.SqlClient; 
Stored XSS
WebGoat/Content/SQLInjectionDiscovery.aspx.cs
Replace lines 28-30


string encodedoutput = Server.HtmlEncode(output);

lblOutput.Text = String.IsNullOrEmpty(output) ? "Customer Number does not exist" : encodedoutput;
